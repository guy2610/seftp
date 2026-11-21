
#pragma once

#include "seftp_server/client_repository.hpp"

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>

namespace seftp::server::persistence {

    enum class SubmitResult { Accepted, Busy, Stopped };

    enum class CompletionStatus { Completed, Cancelled };

    struct RegistrationCompletion {
        CompletionStatus status;
        std::optional<RegistrationResult> result;
    };

    using RegistrationCallback = std::function<void(RegistrationCompletion)>;

    class DbExecutor {
    public:
        explicit DbExecutor(std::string db_path, std::size_t max_outstanding = kMaxOutstanding);

        ~DbExecutor();

        DbExecutor(const DbExecutor&) = delete;
        DbExecutor& operator=(const DbExecutor&) = delete;

        SubmitResult submit_registration(std::string username, RegistrationCallback callback);

        void stop();
        void request_stop();
        void wait();

    private:
        void worker_loop();

        struct RegistrationTask {
            std::string username;
            RegistrationCallback callback;
        };

        static constexpr std::size_t kMaxOutstanding = 32;
        std::size_t max_outstanding_;
        std::size_t outstanding_{0};
        std::mutex mtx_;
        std::condition_variable cv_;
        std::queue<RegistrationTask> queue_;
        bool shutting_down_ = false;
        ClientRepository client_repository_;
        std::thread worker_;
        std::once_flag join_once_;
        bool cancellations_done_{false};
    };

} // namespace seftp::server::persistence
