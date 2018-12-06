#ifndef SL2_DR_ALLOCATOR_H
#define SL2_DR_ALLOCATOR_H

#include <memory>

/**
 * Defines a templatized allocator that's backed by DynamoRIO's private heap.
 * @tparam T - Type to allocate memory for
 */
template <typename T> struct sl2_dr_allocator {
  using value_type = T;

  sl2_dr_allocator() {
  }

  template <typename U> sl2_dr_allocator(const sl2_dr_allocator<U> &) {
  }

  T *allocate(size_t size) {
    return static_cast<T *>(dr_global_alloc(size * sizeof(T)));
  }

  void deallocate(T *ptr, size_t size) {
    dr_global_free(ptr, size);
  }
};

template <class T, class U>
constexpr bool operator==(const sl2_dr_allocator<T> &, const sl2_dr_allocator<U> &) {
  return true;
}

template <class T, class U>
constexpr bool operator!=(const sl2_dr_allocator<T> &, const sl2_dr_allocator<U> &) {
  return false;
}

#endif
