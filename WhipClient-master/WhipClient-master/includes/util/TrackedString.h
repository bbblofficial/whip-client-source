#pragma once
#include <windows.h>
#include <cstring>
#include <string>
#include <vector>

class TrackedStringRegistry {
public:
    static TrackedStringRegistry& instance() {
        static TrackedStringRegistry inst;
        return inst;
    }

    void* allocate(std::size_t size) {
        if (!heap_) return nullptr;
        return HeapAlloc(heap_, HEAP_ZERO_MEMORY, size);
    }

    void deallocate(void* ptr) {
        if (heap_ && ptr) {
            HeapFree(heap_, 0, ptr);
        }
    }

    void track(char* buffer, std::size_t size, bool ownsMemory = false) {
        entries_.push_back({ buffer, size, ownsMemory });
    }

    void track(const char* buffer, std::size_t size, bool ownsMemory = false) {
        track(const_cast<char*>(buffer), size, ownsMemory);
    }

    bool isTracked(const char* buffer) const {
        for (const auto& e : entries_)
            if (e.buffer == buffer) return true;
        return false;
    }

    void untrack(char* buffer) {
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (it->buffer == buffer) {
                entries_.erase(it);
                break;
            }
        }
    }

    void untrack(const char* buffer) {
        untrack(const_cast<char*>(buffer));
    }

    void clearAll() {

        for (auto& e : entries_) {
            if (e.buffer && e.size > 0) {
                SecureZeroMemory(e.buffer, e.size);
                if (e.ownsMemory) {
                    deallocate(e.buffer);
                }
            }
        }
        entries_.clear();

        if (heap_) {
            HeapDestroy(heap_);
            heap_ = nullptr;
        }
    }

private:
    struct Entry {
        char* buffer = nullptr;
        std::size_t size = 0;
        bool ownsMemory = false;
    };

    HANDLE heap_ = nullptr;
    std::vector<Entry> entries_;

    TrackedStringRegistry() {

        heap_ = HeapCreate(0, 0, 0);
    }

    ~TrackedStringRegistry() {
        clearAll();
    }

    TrackedStringRegistry(const TrackedStringRegistry&) = delete;
    TrackedStringRegistry& operator=(const TrackedStringRegistry&) = delete;
};

template<typename T>
struct TrackedAllocator {
    using value_type = T;

    TrackedAllocator() = default;
    template<typename U> TrackedAllocator(const TrackedAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        return static_cast<T*>(TrackedStringRegistry::instance().allocate(n * sizeof(T)));
    }

    void deallocate(T* p, std::size_t) noexcept {
        TrackedStringRegistry::instance().deallocate(p);
    }

    template<typename U>
    bool operator==(const TrackedAllocator<U>&) const noexcept { return true; }
    template<typename U>
    bool operator!=(const TrackedAllocator<U>&) const noexcept { return false; }
};

class DynamicTrackedString {
public:
    DynamicTrackedString() = default;

    explicit DynamicTrackedString(const char* str) {
        if (str) data_ = str;
    }

    explicit DynamicTrackedString(const std::string& str) : data_(str) {}

    ~DynamicTrackedString() { secureClear(); }

    DynamicTrackedString(const DynamicTrackedString& other) : data_(other.data_) {}

    DynamicTrackedString& operator=(const DynamicTrackedString& other) {
        if (this != &other) {
            secureClear();
            data_ = other.data_;
        }
        return *this;
    }

    DynamicTrackedString(DynamicTrackedString&& other) noexcept : data_(std::move(other.data_)) {

        SecureZeroMemory(other.data_.data(), other.data_.capacity());
    }

    DynamicTrackedString& operator=(DynamicTrackedString&& other) noexcept {
        if (this != &other) {
            secureClear();
            data_ = std::move(other.data_);

            SecureZeroMemory(other.data_.data(), other.data_.capacity());
        }
        return *this;
    }

    DynamicTrackedString& operator=(const char* str) {
        secureClear();
        if (str) data_ = str; else data_.clear();
        return *this;
    }

    DynamicTrackedString& operator=(const std::string& str) {
        secureClear();
        data_ = str;
        return *this;
    }

    const char* c_str() const { return data_.c_str(); }
    operator const char*() const { return data_.c_str(); }

    bool        empty() const { return data_.empty(); }
    std::size_t size()  const { return data_.size(); }

    bool operator==(const char* other) const {
        if (!other) return data_.empty();
        return data_ == other;
    }
    bool operator==(const std::string& other)          const { return data_ == other; }
    bool operator==(const DynamicTrackedString& other) const { return data_ == other.data_; }

    bool operator!=(const char* other)                 const { return !operator==(other); }
    bool operator!=(const std::string& other)          const { return !operator==(other); }
    bool operator!=(const DynamicTrackedString& other) const { return !operator==(other); }

    void secureClear() {

        if (data_.capacity() > 0) {
            SecureZeroMemory(data_.data(), data_.capacity());
        }
        data_.clear();
    }

private:
    std::string data_;
};
