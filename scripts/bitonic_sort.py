def bitonic_compare(arr, low, count, direction):
    k = count // 2
    for i in range(low, low + k):
        if (arr[i] > arr[i + k]) == direction:
            arr[i], arr[i + k] = arr[i + k], arr[i]

def bitonic_merge(arr, low, count, direction):
    if count > 1:
        k = count // 2
        bitonic_compare(arr, low, count, direction)
        bitonic_merge(arr, low, k, direction)
        bitonic_merge(arr, low + k, k, direction)

def bitonic_sort(arr, low, count, direction):
    if count > 1:
        k = count // 2
        bitonic_sort(arr, low, k, True)
        bitonic_sort(arr, low + k, k, False)
        bitonic_merge(arr, low, count, direction)

def sort(arr):
    bitonic_sort(arr, 0, len(arr), True)

# Test the algorithm
import random

def test_bitonic_sort():
    # Test with random arrays of different sizes
    for size in [8, 16, 32, 64, 128, 256]:
        arr = [random.randint(1, 1000) for _ in range(size)]
        arr_copy = arr.copy()
        
        print(f"\nTesting with array of size {size}")
        print("Original array:", arr)
        
        sort(arr)
        arr_copy.sort()
        
        print("Sorted array:", arr)
        print("Is correctly sorted:", arr == arr_copy)

    # Test with an array containing duplicates
    arr_duplicates = [3, 1, 4, 1, 5, 9, 2, 6]
    print("\nTesting with array containing duplicates")
    print("Original array:", arr_duplicates)
    
    sort(arr_duplicates)
    
    print("Sorted array:", arr_duplicates)
    print("Is correctly sorted:", arr_duplicates == sorted(arr_duplicates))

if __name__ == "__main__":
    test_bitonic_sort()
