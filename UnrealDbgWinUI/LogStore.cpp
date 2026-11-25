#include "Bridge.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <condition_variable>
#include <thread>
#include <string>
#include <string_view>

namespace
{
    using unrealdbg_native::LogLevel;
    using unrealdbg_native::LogRecord;

    constexpr size_t kMaximumPendingRecords = 5000;
    constexpr size_t kTrimBatch = 1000;
    constexpr std::uintmax_t kMaximumLogBytes = 8u * 1024u * 1024u;
    constexpr size_t kMaximumExternalCharacters = 32768;

    std::string ToUtf8(const std::wstring_view text)
    {
        if (text.empty())
        {
            return {};
        }

        const int required = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0)
        {
            return {};
        }

        std::string result(static_cast<size_t>(required), '\0');
        if (::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            text.data(), static_cast<int>(text.size()), result.data(), required,
            nullptr, nullptr) != required)
        {
            return {};
        }
        return result;
    }

    std::wstring Timestamp()
    {
        SYSTEMTIME time{};
        ::GetLocalTime(&time);
        wchar_t buffer[40]{};
        swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
            time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
            time.wSecond, time.wMilliseconds);
        return buffer;
    }

    const wchar_t* LevelText(const LogLevel level) noexcept
    {
        switch (level)
        {
        case LogLevel::Debug:
            return L"调试";
        case LogLevel::Error:
            return L"错误";
        case LogLevel::Info:
        default:
            return L"信息";
        }
    }

    bool ContainsInsensitive(const std::wstring_view text, const std::wstring_view needle)
    {
        if (needle.empty() || needle.size() > text.size())
        {
            return false;
        }
        auto lower = [](wchar_t value)
        {
            if (value >= L'A' && value <= L'Z')
            {
                return static_cast<wchar_t>(value - L'A' + L'a');
            }
            return value;
        };

        for (size_t index = 0; index + needle.size() <= text.size(); ++index)
        {
            size_t inner = 0;
            for (; inner < needle.size(); ++inner)
            {
                if (lower(text[index + inner]) != lower(needle[inner]))
                {
                    break;
                }
            }
            if (inner == needle.size())
            {
                return true;
            }
        }
        return false;
    }

    LogLevel ClassifyExternalText(const std::wstring_view text) noexcept
    {
        if (ContainsInsensitive(text, L"[错误]") ||
            ContainsInsensitive(text, L"错误") ||
            ContainsInsensitive(text, L"失败") ||
            ContainsInsensitive(text, L"异常") ||
            ContainsInsensitive(text, L"error") ||
            ContainsInsensitive(text, L"fatal"))
        {
            return LogLevel::Error;
        }

        if (ContainsInsensitive(text, L"[调试]") ||
            ContainsInsensitive(text, L"debug") ||
            ContainsInsensitive(text, L"trace"))
        {
            return LogLevel::Debug;
        }

        return LogLevel::Info;
    }

    class LogStore final
    {
    public:
        ~LogStore() { Reset(); }

        void Configure(const std::wstring& applicationDirectory)
        {
            std::lock_guard lifecycle(lifecycleMutex_);
            Stop();
            if (applicationDirectory.empty()) return;
            std::error_code error;
            const auto directory = std::filesystem::path(applicationDirectory) / L"Log";
            std::filesystem::create_directories(directory, error);
            if (error) return;
            logPath_ = directory / L"WinUI.log";
            const auto size = std::filesystem::file_size(logPath_, error);
            fileBytes_ = error ? 0 : size;
            {
                std::lock_guard lock(mutex_);
                stopping_ = false;
                sequence_ = 0;
            }
            try { worker_ = std::thread([this] { Run(); }); }
            catch (...)
            {
                std::lock_guard lock(mutex_);
                stopping_ = true;
                throw;
            }
        }

        void Reset() noexcept
        {
            std::lock_guard lifecycle(lifecycleMutex_);
            Stop();
        }

        void Push(const LogLevel level, const std::wstring_view text)
        {
            if (text.empty()) return;
            std::wstring line = L"[" + Timestamp() + L"] [" + LevelText(level) + L"] ";
            line.append(text.data(), (std::min)(text.size(), kMaximumExternalCharacters));
            while (!line.empty() && (line.back() == L'\r' || line.back() == L'\n'))
                line.pop_back();
            line += L"\r\n";
            std::string utf8 = ToUtf8(line);
            std::lock_guard lock(mutex_);
            if (stopping_) return;
            // UI records and disk records have independent, bounded queues.
            pendingBytes_ += line.size() * sizeof(wchar_t);
            pending_.push_back(LogRecord{ level, std::move(line) });
            while (pending_.size() > kMaximumPendingRecords || pendingBytes_ > kMaximumQueueBytes)
            {
                const auto count = (std::min)(pending_.size(), kTrimBatch);
                for (size_t i = 0; i < count; ++i)
                    pendingBytes_ -= pending_[i].text.size() * sizeof(wchar_t);
                pending_.erase(pending_.begin(), pending_.begin() + count);
            }
            sequence_.fetch_add(1, std::memory_order_release);
            if (diskBytes_ + utf8.size() <= kMaximumQueueBytes &&
                disk_.size() < kMaximumPendingRecords)
            {
                const auto bytes = utf8.size();
                disk_.push_back(std::move(utf8));
                diskBytes_ += bytes;
            }
            else ++dropped_;
            if (diskBytes_ >= kBatchBytes) wake_.notify_one();
        }

        void Drain(std::vector<LogRecord>& records)
        {
            std::lock_guard lock(mutex_);
            records.insert(records.end(), std::make_move_iterator(pending_.begin()),
                std::make_move_iterator(pending_.end()));
            pending_.clear();
            pendingBytes_ = 0;
        }

        std::uint32_t Count() const noexcept
        {
            return sequence_.load(std::memory_order_acquire);
        }

    private:
        void Stop() noexcept
        {
            {
                std::lock_guard lock(mutex_);
                stopping_ = true;
            }
            wake_.notify_one();
            if (worker_.joinable()) worker_.join();
            std::lock_guard lock(mutex_);
            pending_.clear();
            disk_.clear();
            pendingBytes_ = diskBytes_ = dropped_ = 0;
        }

        bool Append(std::ofstream& file, const std::string& text)
        {
            std::error_code error;
            if (fileBytes_ && fileBytes_ + text.size() > kMaximumLogBytes)
            {
                file.close();
                const auto previous = logPath_.parent_path() / L"WinUI.previous.log";
                std::filesystem::remove(previous, error);
                if (error) return false;
                std::filesystem::rename(logPath_, previous, error);
                if (error) return false; // Do not grow an unrotatable file indefinitely.
                fileBytes_ = 0;
            }
            if (!file.is_open())
            {
                file.clear();
                file.open(logPath_, std::ios::binary | std::ios::app);
            }
            if (!file) return false;
            file.write(text.data(), static_cast<std::streamsize>(text.size()));
            if (!file) { file.close(); return false; }
            fileBytes_ += text.size();
            return true;
        }

        void Run() noexcept
        {
            try
            {
                std::ofstream file;
                for (;;)
                {
                    std::vector<std::string> batch;
                    size_t dropped = 0;
                    bool done = false;
                    {
                        std::unique_lock lock(mutex_);
                        wake_.wait_for(lock, std::chrono::milliseconds(100),
                            [this] { return stopping_ || diskBytes_ >= kBatchBytes; });
                        batch.swap(disk_);
                        diskBytes_ = 0;
                        dropped = dropped_;
                        dropped_ = 0;
                        done = stopping_;
                    }
                    bool ok = true;
                    if (dropped)
                        ok = Append(file, "[LogStore] queue full, dropped " +
                            std::to_string(dropped) + " records\r\n");
                    for (const auto& line : batch) ok = Append(file, line) && ok;
                    if (file.is_open()) { file.flush(); ok = bool(file) && ok; }
                    if (!ok) ::OutputDebugStringW(L"LogStore: write/rotation failed\n");
                    if (done) break; // The last accepted batch has been written and flushed.
                }
            }
            catch (...) { ::OutputDebugStringW(L"LogStore: writer failed\n"); }
        }

        static constexpr size_t kMaximumQueueBytes = 4u * 1024u * 1024u;
        static constexpr size_t kBatchBytes = 256u * 1024u;
        std::mutex lifecycleMutex_;
        mutable std::mutex mutex_;
        std::condition_variable wake_;
        std::thread worker_;
        bool stopping_{ true };
        std::vector<LogRecord> pending_;
        std::vector<std::string> disk_;
        size_t pendingBytes_{}, diskBytes_{}, dropped_{};
        std::filesystem::path logPath_;
        std::uintmax_t fileBytes_{};
        std::atomic<std::uint32_t> sequence_{ 0 };
    };

    LogStore g_logStore;
}

namespace unrealdbg_native
{
    void ConfigureLogStore(const std::wstring& applicationDirectory)
    {
        g_logStore.Configure(applicationDirectory);
    }

    void ShutdownLogStore() noexcept
    {
        g_logStore.Reset();
    }

    void WriteLog(const LogLevel level, const std::wstring_view text)
    {
        g_logStore.Push(level, text);
    }

    void DrainLogs(std::vector<LogRecord>& records)
    {
        g_logStore.Drain(records);
    }

    std::uint32_t LogCount() noexcept
    {
        return g_logStore.Count();
    }
}

extern "C" __declspec(dllexport) void __stdcall PrintLog(wchar_t* text)
{
    if (text == nullptr)
    {
        unrealdbg_native::WriteLog(unrealdbg_native::LogLevel::Error,
            L"PrintLog 收到空指针");
        return;
    }

    size_t length = 0;
    while (length < kMaximumExternalCharacters && text[length] != L'\0')
    {
        ++length;
    }

    const std::wstring_view message(text, length);
    unrealdbg_native::WriteLog(ClassifyExternalText(message), message);
}
