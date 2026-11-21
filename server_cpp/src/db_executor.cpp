#include "seftp_server/db_executor.hpp"

#include <iostream>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace seftp::server::persistence {
    DbExecutor::DbExecutor(std::string db_path, std::size_t max_outstanding)
        : max_outstanding_(max_outstanding), client_repository_(db_path) {
        if (max_outstanding == 0 || max_outstanding > kMaxOutstanding) {
            throw std::invalid_argument("Invalid max_outstanding");
        }
        worker_ = std::thread([this] {
            worker_loop();
        });
    }
    DbExecutor::~DbExecutor() { stop(); }

    void DbExecutor::request_stop() {
        std::queue<RegistrationTask> cancelled_tasks;
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (shutting_down_) {
                return;
            }
            shutting_down_ = true;
            const auto cancelled_count = queue_.size();
            queue_.swap(cancelled_tasks);
            outstanding_ -= cancelled_count;
        }

        cv_.notify_all();

        while (!cancelled_tasks.empty()) {
            RegistrationTask task = std::move(cancelled_tasks.front());
            cancelled_tasks.pop();

            try {
                if (task.callback) {
                    task.callback({CompletionStatus::Cancelled, std::nullopt});
                }
            } catch (const std::exception& e) {
                std::cerr << "Cancellation callback failed: " << e.what() << '\n';
            } catch (...) {
                std::cerr << "Unknown cancellation callback failure\n";
            }
        }

        {
            std::lock_guard<std::mutex> lock(mtx_);
            cancellations_done_ = true;
        }
        cv_.notify_all();
    }

    void DbExecutor::wait() {
        request_stop();

        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this] {
                return cancellations_done_;
            });
        }
        std::call_once(join_once_, [this] {
            if (worker_.joinable()) {
                worker_.join();
            }
        });
    }

    void DbExecutor::stop() {
        wait();
    }

    SubmitResult DbExecutor::submit_registration(std::string username,
                                                 RegistrationCallback callback) {

        if (!callback) {
            throw std::invalid_argument("Registration callback must not be empty");
        }

        {
            std::lock_guard<std::mutex> lock(mtx_);

            if (shutting_down_) {
                return SubmitResult::Stopped;
            }
            if (outstanding_ >= max_outstanding_) {
                return SubmitResult::Busy;
            }
            queue_.push({std::move(username), std::move(callback)});
            ++outstanding_;
        }

        cv_.notify_one();
        return SubmitResult::Accepted;
    }

    void DbExecutor::worker_loop() {
        while (true) {
            RegistrationTask task;
            RegistrationResult registration_result{RegistrationStatus::StorageError, {}};

            {
                std::unique_lock<std::mutex> lock(mtx_);

                cv_.wait(lock, [this] {
                    return !queue_.empty() || shutting_down_;
                });

                if (shutting_down_) {
                    break;
                }

                task = std::move(queue_.front());
                queue_.pop();
            }
            try {
                registration_result = client_repository_.register_client(task.username);
            } catch (const std::exception& e) {
                std::cerr << "DB registration failed: " << e.what() << '\n';
            } catch (...) {
                std::cerr << "Unknown DB registration failure\n";
            }

            {
                std::lock_guard<std::mutex> lock(mtx_);
                --outstanding_;
            }
            try {
                task.callback({CompletionStatus::Completed, registration_result});
            } catch (const std::exception& e) {
                std::cerr << "DB callback failed: " << e.what() << '\n';
            } catch (...) {
                std::cerr << "Unknown DB callback failure\n";
            }
        }
    }

} // namespace seftp::server::persistence
