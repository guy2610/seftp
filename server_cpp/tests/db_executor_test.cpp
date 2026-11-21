
#include "seftp_server/db_executor.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <memory>
#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

    namespace persistence = seftp::server::persistence;

    class TemporaryDatabase {
    public:
        TemporaryDatabase() {
            static std::atomic<unsigned> counter{0};

            const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();

            directory_ = std::filesystem::temp_directory_path() /
                         ("seftp_db_executor_" + std::to_string(ticks) + "_" +
                          std::to_string(counter.fetch_add(1)));

            if (!std::filesystem::create_directory(directory_)) {
                throw std::runtime_error("Cannot create test directory");
            }
        }

        ~TemporaryDatabase() {
            std::error_code ignored;
            std::filesystem::remove_all(directory_, ignored);
        }

        std::string path() const { return (directory_ / "test.sqlite").string(); }

    private:
        std::filesystem::path directory_;
    };

    struct Completion {
        persistence::RegistrationCompletion result;
        std::thread::id callback_thread;
    };

    TEST(DbExecutorTest, ExecutesRegistrationOnWorkerThread) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path());

        auto completion = std::make_shared<std::promise<Completion>>();
        auto future = completion->get_future();

        const auto caller_thread = std::this_thread::get_id();

        const auto submit_result = executor.submit_registration(
            "alice", [completion](persistence::RegistrationCompletion result) {
                completion->set_value(Completion{result, std::this_thread::get_id()});
            });

        ASSERT_EQ(submit_result, persistence::SubmitResult::Accepted);

        ASSERT_EQ(future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        const auto completed = future.get();

        EXPECT_EQ(completed.result.status, persistence::CompletionStatus::Completed);
        ASSERT_TRUE(completed.result.result.has_value());
        EXPECT_EQ(completed.result.result->status, persistence::RegistrationStatus::Created);

        EXPECT_NE(completed.callback_thread, caller_thread);
    }

    TEST(DbExecutorTest, RejectsWhenPendingQueueIsFull) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path(), 2);

        auto entered = std::make_shared<std::promise<void>>();
        auto entered_future = entered->get_future();

        auto release = std::make_shared<std::promise<void>>();
        auto release_future = release->get_future().share();

        const auto first = executor.submit_registration(
            "alice", [entered, release_future](persistence::RegistrationCompletion) {
                entered->set_value();

                // Bounded wait prevents an indefinite test hang.
                release_future.wait_for(std::chrono::seconds(5));
            });

        ASSERT_EQ(first, persistence::SubmitResult::Accepted);

        ASSERT_EQ(entered_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        EXPECT_EQ(executor.submit_registration("bob",
                                               [](auto) {
                                               }),
                  persistence::SubmitResult::Accepted);

        EXPECT_EQ(executor.submit_registration("charlie",
                                               [](auto) {
                                               }),
                  persistence::SubmitResult::Accepted);

        EXPECT_EQ(executor.submit_registration("david",
                                               [](auto) {
                                               }),
                  persistence::SubmitResult::Busy);

        release->set_value();
    }

    TEST(DbExecutorTest, CallbackExceptionDoesNotStopWorker) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path());

        auto completion = std::make_shared<std::promise<persistence::RegistrationCompletion>>();

        auto future = completion->get_future();

        const auto first =
            executor.submit_registration("alice", [](persistence::RegistrationCompletion) {
                throw std::runtime_error("Injected callback failure");
            });

        ASSERT_EQ(first, persistence::SubmitResult::Accepted);

        const auto second = executor.submit_registration(
            "bob", [completion](persistence::RegistrationCompletion result) {
                completion->set_value(result);
            });

        ASSERT_EQ(second, persistence::SubmitResult::Accepted);

        ASSERT_EQ(future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        const auto completed = future.get();
        EXPECT_EQ(completed.status, persistence::CompletionStatus::Completed);
        ASSERT_TRUE(completed.result.has_value());
        EXPECT_EQ(completed.result->status, persistence::RegistrationStatus::Created);
    }

    TEST(DbExecutorTest, StopRejectsNewSubmissionsAndIsIdempotent) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path());

        executor.stop();
        executor.stop();

        std::atomic<bool> callback_called{false};

        const auto result = executor.submit_registration(
            "alice", [&callback_called](persistence::RegistrationCompletion) {
                callback_called.store(true);
            });

        EXPECT_EQ(result, persistence::SubmitResult::Stopped);
        EXPECT_FALSE(callback_called.load());
    }

    TEST(DbExecutorTest, StopCancelsQueuedRegistrations) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path(), 3);

        std::promise<void> entered;
        auto entered_future = entered.get_future();

        std::promise<void> release;
        auto release_future = release.get_future().share();

        ASSERT_EQ(executor.submit_registration(
                      "alice",
                      [&entered, release_future](persistence::RegistrationCompletion) {
                          entered.set_value();
                          release_future.wait_for(std::chrono::seconds(5));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(entered_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        std::promise<persistence::RegistrationCompletion> bob_promise;
        std::promise<persistence::RegistrationCompletion> charlie_promise;

        auto bob_future = bob_promise.get_future();
        auto charlie_future = charlie_promise.get_future();

        ASSERT_EQ(executor.submit_registration(
                      "bob",
                      [&bob_promise](persistence::RegistrationCompletion result) {
                          bob_promise.set_value(std::move(result));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(executor.submit_registration(
                      "charlie",
                      [&charlie_promise](persistence::RegistrationCompletion result) {
                          charlie_promise.set_value(std::move(result));
                      }),
                  persistence::SubmitResult::Accepted);

        std::thread stopper([&executor] {
            executor.stop();
        });

        const auto bob_status = bob_future.wait_for(std::chrono::seconds(2));
        const auto charlie_status = charlie_future.wait_for(std::chrono::seconds(2));

        // Release the active callback before joining the worker.
        release.set_value();
        stopper.join();

        ASSERT_EQ(bob_status, std::future_status::ready);
        ASSERT_EQ(charlie_status, std::future_status::ready);

        const auto bob = bob_future.get();
        const auto charlie = charlie_future.get();

        EXPECT_EQ(bob.status, persistence::CompletionStatus::Cancelled);
        EXPECT_FALSE(bob.result.has_value());

        EXPECT_EQ(charlie.status, persistence::CompletionStatus::Cancelled);
        EXPECT_FALSE(charlie.result.has_value());

        // Verify neither queued registration was committed.
        persistence::ClientRepository verification(database.path());

        EXPECT_EQ(verification.register_client("bob").status,
                  persistence::RegistrationStatus::Created);

        EXPECT_EQ(verification.register_client("charlie").status,
                  persistence::RegistrationStatus::Created);
    }

    TEST(DbExecutorTest, ConcurrentSubmissionsRespectCapacity) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path(), 4);

        std::promise<void> entered;
        auto entered_future = entered.get_future();

        std::promise<void> release;
        auto release_future = release.get_future().share();

        ASSERT_EQ(executor.submit_registration(
                      "initial_user",
                      [&entered, release_future](persistence::RegistrationCompletion) {
                          entered.set_value();
                          release_future.wait_for(std::chrono::seconds(5));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(entered_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        std::atomic<int> accepted{0};
        std::atomic<int> busy{0};
        std::atomic<int> stopped{0};

        std::vector<std::thread> producers;

        constexpr int kThreads = 8;
        constexpr int kRequestsPerThread = 6;

        for (int i = 0; i < kThreads; ++i) {
            producers.emplace_back([&, i] {
                for (int j = 0; j < kRequestsPerThread; ++j) {
                    const auto username = "user_" + std::to_string(i) + "_" + std::to_string(j);

                    const auto result = executor.submit_registration(
                        username, [](persistence::RegistrationCompletion) {
                        });

                    switch (result) {
                    case persistence::SubmitResult::Accepted:
                        ++accepted;
                        break;
                    case persistence::SubmitResult::Busy:
                        ++busy;
                        break;
                    case persistence::SubmitResult::Stopped:
                        ++stopped;
                        break;
                    }
                }
            });
        }

        for (auto& producer : producers) {
            producer.join();
        }

        EXPECT_EQ(accepted.load(), 4);
        EXPECT_EQ(busy.load(), 44);
        EXPECT_EQ(stopped.load(), 0);

        release.set_value();
    }

    TEST(DbExecutorTest, CancellationCallbackExceptionDoesNotSkipOtherTasks) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path(), 3);

        std::promise<void> entered;
        auto entered_future = entered.get_future();

        std::promise<void> release;
        auto release_future = release.get_future().share();

        ASSERT_EQ(executor.submit_registration(
                      "alice",
                      [&entered, release_future](persistence::RegistrationCompletion) {
                          entered.set_value();
                          release_future.wait_for(std::chrono::seconds(5));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(entered_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        std::promise<persistence::RegistrationCompletion> charlie_completion;
        auto charlie_future = charlie_completion.get_future();

        ASSERT_EQ(executor.submit_registration(
                      "bob",
                      [](persistence::RegistrationCompletion result) {
                          if (result.status == persistence::CompletionStatus::Cancelled) {
                              throw std::runtime_error("Injected cancellation failure");
                          }
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(executor.submit_registration(
                      "charlie",
                      [&charlie_completion](persistence::RegistrationCompletion result) {
                          charlie_completion.set_value(std::move(result));
                      }),
                  persistence::SubmitResult::Accepted);

        std::thread stopper([&executor] {
            executor.stop();
        });

        const auto status = charlie_future.wait_for(std::chrono::seconds(2));

        release.set_value();
        stopper.join();

        ASSERT_EQ(status, std::future_status::ready);

        const auto result = charlie_future.get();
        EXPECT_EQ(result.status, persistence::CompletionStatus::Cancelled);
        EXPECT_FALSE(result.result.has_value());
    }

    TEST(DbExecutorTest, CallbackCanRequestStop) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path());

        std::promise<void> callback_finished;
        auto callback_future = callback_finished.get_future();

        const auto submit_result = executor.submit_registration(
            "alice",
            [&executor, &callback_finished](persistence::RegistrationCompletion completion) {
                EXPECT_EQ(completion.status, persistence::CompletionStatus::Completed);

                executor.request_stop();
                callback_finished.set_value();
            });

        ASSERT_EQ(submit_result, persistence::SubmitResult::Accepted);

        const auto status = callback_future.wait_for(std::chrono::seconds(5));

        if (status == std::future_status::ready) {
            executor.wait();
        }

        EXPECT_EQ(status, std::future_status::ready);

        EXPECT_EQ(executor.submit_registration("bob",
                                               [](persistence::RegistrationCompletion) {
                                               }),
                  persistence::SubmitResult::Stopped);
    }

    TEST(DbExecutorTest, ConcurrentStopCancelsEachTaskOnce) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path(), 3);

        std::promise<void> active_entered;
        auto active_entered_future = active_entered.get_future();

        std::promise<void> release_active;
        auto active_gate = release_active.get_future().share();

        ASSERT_EQ(executor.submit_registration(
                      "alice",
                      [&active_entered, active_gate](persistence::RegistrationCompletion) {
                          active_entered.set_value();
                          active_gate.wait_for(std::chrono::seconds(10));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(active_entered_future.wait_for(std::chrono::seconds(5)),
                  std::future_status::ready);

        std::promise<void> cancellation_entered;
        auto cancellation_future = cancellation_entered.get_future();

        std::promise<void> release_cancellation;
        auto cancellation_gate = release_cancellation.get_future().share();

        std::atomic<int> bob_cancelled{0};
        std::atomic<int> charlie_cancelled{0};
        std::atomic<int> unexpected{0};

        ASSERT_EQ(executor.submit_registration(
                      "bob",
                      [&](persistence::RegistrationCompletion result) {
                          if (result.status == persistence::CompletionStatus::Cancelled &&
                              !result.result.has_value()) {
                              ++bob_cancelled;
                          } else {
                              ++unexpected;
                          }

                          cancellation_entered.set_value();
                          cancellation_gate.wait_for(std::chrono::seconds(10));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(executor.submit_registration(
                      "charlie",
                      [&](persistence::RegistrationCompletion result) {
                          if (result.status == persistence::CompletionStatus::Cancelled &&
                              !result.result.has_value()) {
                              ++charlie_cancelled;
                          } else {
                              ++unexpected;
                          }
                      }),
                  persistence::SubmitResult::Accepted);

        std::thread first_stopper([&] {
            executor.stop();
        });

        const auto cancellation_started = cancellation_future.wait_for(std::chrono::seconds(5));

        std::thread second_stopper([&] {
            executor.stop();
        });

        // Release both callbacks before joining either thread.
        release_cancellation.set_value();
        release_active.set_value();

        first_stopper.join();
        second_stopper.join();

        ASSERT_EQ(cancellation_started, std::future_status::ready);
        EXPECT_EQ(bob_cancelled.load(), 1);
        EXPECT_EQ(charlie_cancelled.load(), 1);
        EXPECT_EQ(unexpected.load(), 0);
    }

    TEST(DbExecutorTest, ConcurrentSubmitAndStopDoNotLoseTasks) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path(), 8);

        std::promise<void> active_entered;
        auto active_entered_future = active_entered.get_future();

        std::promise<void> release_active;
        auto active_gate = release_active.get_future().share();

        ASSERT_EQ(executor.submit_registration(
                      "initial_user",
                      [&active_entered, active_gate](persistence::RegistrationCompletion) {
                          active_entered.set_value();
                          active_gate.wait_for(std::chrono::seconds(10));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(active_entered_future.wait_for(std::chrono::seconds(5)),
                  std::future_status::ready);

        std::atomic<int> accepted{0};
        std::atomic<int> busy{0};
        std::atomic<int> stopped{0};
        std::atomic<int> completed{0};
        std::atomic<int> cancelled{0};
        std::atomic<int> invalid{0};

        auto callback = [&](persistence::RegistrationCompletion result) {
            if (result.status == persistence::CompletionStatus::Completed &&
                result.result.has_value()) {
                ++completed;
            } else if (result.status == persistence::CompletionStatus::Cancelled &&
                       !result.result.has_value()) {
                ++cancelled;
            } else {
                ++invalid;
            }
        };

        // Ensure some tasks are queued before shutdown begins.
        for (int i = 0; i < 4; ++i) {
            ASSERT_EQ(executor.submit_registration("queued_" + std::to_string(i), callback),
                      persistence::SubmitResult::Accepted);
            ++accepted;
        }

        std::promise<void> start;
        auto start_gate = start.get_future().share();

        std::vector<std::thread> producers;

        constexpr int kProducerCount = 8;
        constexpr int kRequestsPerProducer = 20;

        for (int i = 0; i < kProducerCount; ++i) {
            producers.emplace_back([&, i] {
                start_gate.wait();

                for (int j = 0; j < kRequestsPerProducer; ++j) {
                    auto result = executor.submit_registration(
                        "user_" + std::to_string(i) + "_" + std::to_string(j), callback);

                    switch (result) {
                    case persistence::SubmitResult::Accepted:
                        ++accepted;
                        break;
                    case persistence::SubmitResult::Busy:
                        ++busy;
                        break;
                    case persistence::SubmitResult::Stopped:
                        ++stopped;
                        break;
                    }
                }
            });
        }

        std::thread stopper([&] {
            start_gate.wait();
            executor.stop();
        });

        start.set_value();

        for (auto& producer : producers) {
            producer.join();
        }

        release_active.set_value();
        stopper.join();

        constexpr int total_submissions = 4 + kProducerCount * kRequestsPerProducer;

        EXPECT_EQ(accepted.load() + busy.load() + stopped.load(), total_submissions);

        EXPECT_EQ(completed.load() + cancelled.load(), accepted.load());

        EXPECT_EQ(invalid.load(), 0);

        EXPECT_EQ(executor.submit_registration("late_user", callback),
                  persistence::SubmitResult::Stopped);
    }

    TEST(DbExecutorTest, DatabaseFailureDoesNotStopWorker) {
        TemporaryDatabase database;

        // Initialize the schema before installing the failure trigger.
        {
            persistence::ClientRepository repo(database.path());
        }

        // Reject INSERT operations for alice only.
        {
            sqlite3* raw_db = nullptr;

            const int open_rc =
                sqlite3_open_v2(database.path().c_str(), &raw_db, SQLITE_OPEN_READWRITE, nullptr);

            std::unique_ptr<sqlite3, decltype(&sqlite3_close)> db(raw_db, sqlite3_close);

            ASSERT_EQ(open_rc, SQLITE_OK);

            const char* sql = R"(
            CREATE TRIGGER reject_alice
            BEFORE INSERT ON Clients
            WHEN NEW.username = 'alice'
            BEGIN
                SELECT RAISE(FAIL, 'injected database failure');
            END;
        )";

            ASSERT_EQ(sqlite3_exec(db.get(), sql, nullptr, nullptr, nullptr), SQLITE_OK);
        }

        persistence::DbExecutor executor(database.path());

        std::promise<persistence::RegistrationCompletion> alice_promise;
        std::promise<persistence::RegistrationCompletion> bob_promise;

        auto alice_future = alice_promise.get_future();
        auto bob_future = bob_promise.get_future();

        ASSERT_EQ(executor.submit_registration(
                      "alice",
                      [&alice_promise](persistence::RegistrationCompletion result) {
                          alice_promise.set_value(std::move(result));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(executor.submit_registration(
                      "bob",
                      [&bob_promise](persistence::RegistrationCompletion result) {
                          bob_promise.set_value(std::move(result));
                      }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(alice_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        ASSERT_EQ(bob_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        const auto alice = alice_future.get();
        const auto bob = bob_future.get();

        ASSERT_EQ(alice.status, persistence::CompletionStatus::Completed);
        ASSERT_TRUE(alice.result.has_value());
        EXPECT_EQ(alice.result->status, persistence::RegistrationStatus::StorageError);

        ASSERT_EQ(bob.status, persistence::CompletionStatus::Completed);
        ASSERT_TRUE(bob.result.has_value());
        EXPECT_EQ(bob.result->status, persistence::RegistrationStatus::Created);
    }

    TEST(DbExecutorTest, WaitIncludesCancellationCallbacks) {
        TemporaryDatabase database;
        persistence::DbExecutor executor(database.path(), 2);

        std::promise<void> worker_entered;
        std::promise<void> release_worker;
        std::promise<void> cancellation_entered;
        std::promise<void> release_cancellation;

        auto worker_started = worker_entered.get_future();
        auto cancellation_started = cancellation_entered.get_future();

        auto worker_gate = release_worker.get_future().share();
        auto cancellation_gate = release_cancellation.get_future().share();

        ASSERT_EQ(executor.submit_registration("alice",
                                               [&](persistence::RegistrationCompletion) {
                                                   worker_entered.set_value();
                                                   worker_gate.wait_for(std::chrono::seconds(5));
                                               }),
                  persistence::SubmitResult::Accepted);

        ASSERT_EQ(worker_started.wait_for(std::chrono::seconds(5)), std::future_status::ready);

        ASSERT_EQ(executor.submit_registration(
                      "bob",
                      [&](persistence::RegistrationCompletion result) {
                          EXPECT_EQ(result.status, persistence::CompletionStatus::Cancelled);
                          cancellation_entered.set_value();
                          cancellation_gate.wait_for(std::chrono::seconds(5));
                      }),
                  persistence::SubmitResult::Accepted);

        std::thread requester([&] {
            executor.request_stop();
        });

        const auto cancellation_status = cancellation_started.wait_for(std::chrono::seconds(5));

        release_worker.set_value();

        auto waiter = std::async(std::launch::async, [&] {
            executor.wait();
        });

        const auto before_release = waiter.wait_for(std::chrono::milliseconds(200));

        release_cancellation.set_value();
        requester.join();

        const auto after_release = waiter.wait_for(std::chrono::seconds(5));

        EXPECT_EQ(cancellation_status, std::future_status::ready);
        EXPECT_EQ(before_release, std::future_status::timeout);
        EXPECT_EQ(after_release, std::future_status::ready);
    }

} // namespace
