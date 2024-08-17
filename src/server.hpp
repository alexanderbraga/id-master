#pragma once

#include "server_base.hpp"
#include "server_list.hpp"
#include "client_list.hpp"
#include "service.hpp"
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <mutex>
#include <deque>

class RateLimiter {
public:
    RateLimiter(size_t max_requests, std::chrono::seconds window)
        : max_requests_(max_requests), window_(window) {}

    bool allow(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& entry = requests_[ip];
        auto now = std::chrono::steady_clock::now();

        // Remove old requests
        while (!entry.empty() && now - entry.front() > window_) {
            entry.pop_front();
        }

        if (entry.size() < max_requests_) {
            entry.push_back(now);
            return true;
        }

        return false;
    }

private:
    size_t max_requests_;
    std::chrono::seconds window_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> requests_;
    std::mutex mutex_;
};

class server : public server_base
{
public:
    server(const network::address& bind_addr)
        : rate_limiter_(100, std::chrono::seconds(60)) // 100 requests per minute
    {
        // Initialization code
    }

    server_list& get_server_list();
    const server_list& get_server_list() const;

    client_list& get_client_list();
    const client_list& get_client_list() const;

    template <typename T>
    T* get_service()
    {
        static_assert(std::is_base_of_v<service, T>, "Type must be a service!");

        for (auto& service : this->services_)
        {
            const auto& service_ref = *service;
            if (typeid(service_ref) == typeid(T))
            {
                return reinterpret_cast<T*>(service.get());
            }
        }

        return nullptr;
    }

    void block_ip(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(ip);
    }

    void unblock_ip(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.erase(ip);
    }

    bool is_ip_blocked(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_ips_.find(ip) != blocked_ips_.end();
    }

    void handle_request(const std::string& client_ip) {
        if (is_ip_blocked(client_ip) || !rate_limiter_.allow(client_ip)) {
            // Reject request
            return;
        }

        // Process request
    }

private:
    server_list server_list_;
    client_list client_list_;

    std::vector<std::unique_ptr<service>> services_;
    std::unordered_map<std::string, service*> command_services_;
    RateLimiter rate_limiter_;
    std::unordered_set<std::string> blocked_ips_;
    std::mutex mutex_;

    template <typename T, typename... Args>
    void register_service(Args&&... args)
    {
        static_assert(std::is_base_of_v<service, T>, "Type must be a service!");

        auto service = std::make_unique<T>(*this, std::forward<Args>(args)...);
        auto* const command = service->get_command();
        if (command)
        {
            command_services_[command] = service.get();
        }

        services_.emplace_back(std::move(service));
    }

    void run_frame() override;
    void handle_command(const network::address& target, const std::string_view& command,
                        const std::string_view& data) override;
};