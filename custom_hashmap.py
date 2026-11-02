"""
custom_hashmap.py

A custom implementation of a hash map (dictionary) using chaining for collision
resolution. This data structure is used as the underlying tracker for anomaly
detection, mapping source IPs to their corresponding data queues.
"""

class CustomHashMap:
    """A custom hash map implementation using chaining for collision resolution."""

    class _HashNode:
        """A private inner class representing a node in the hash map's collision chain."""
        def __init__(self, key, value):
            self.key = key
            self.value = value
            self.next = None

    def __init__(self, initial_capacity=16, load_factor_threshold=0.75):
        """Initialize the hash map with a list of buckets."""
        if initial_capacity <= 0:
            raise ValueError("Initial capacity must be a positive integer.")
        self.capacity = initial_capacity
        self.load_factor_threshold = load_factor_threshold
        self.buckets = [None] * self.capacity
        self.size = 0

    def _hash_function(self, key: str) -> int:
        """Simple polynomial rolling hash function for string keys."""
        # Ensure key is a string for consistent hashing
        key = str(key)
        
        hash_value = 0
        prime = 31
        
        for char in key:
            hash_value = (hash_value * prime + ord(char)) % self.capacity
        
        return hash_value

    def insert(self, key: str, value):
        """Insert or update a key-value pair in the hash map."""
        if (self.size / self.capacity) >= self.load_factor_threshold:
            self._resize(self.capacity * 2)

        index = self._hash_function(key)
        
        # Check if the key already exists in the chain and update its value
        current = self.buckets[index]
        while current:
            if current.key == key:
                current.value = value
                return
            current = current.next
        
        # If the key is new, add a new node to the beginning of the chain
        new_node = self._HashNode(key, value)
        new_node.next = self.buckets[index]
        self.buckets[index] = new_node
        self.size += 1

    def get(self, key: str, default_value=None):
        """Retrieve a value for a key, returning a default value if not found."""
        index = self._hash_function(key)
        
        current = self.buckets[index]
        while current:
            if current.key == key:
                return current.value
            current = current.next
        
        return default_value

    def contains(self, key: str) -> bool:
        """Check if a key exists in the hash map."""
        return self.get(key) is not None

    def _resize(self, new_capacity: int):
        """Resize the hash map to a new capacity and rehash all items."""
        old_buckets = self.buckets
        self.capacity = new_capacity
        self.buckets = [None] * new_capacity
        self.size = 0

        for bucket in old_buckets:
            current = bucket
            while current:
                self.insert(current.key, current.value)
                current = current.next

    def __iter__(self):
        """Allows iteration over the keys of the hash map."""
        for bucket in self.buckets:
            current = bucket
            while current:
                yield current.key
                current = current.next

    def __len__(self) -> int:
        """Return the number of key-value pairs in the hash map."""
        return self.size

    def is_empty(self) -> bool:
        """Check if the hash map is empty."""
        return self.size == 0
