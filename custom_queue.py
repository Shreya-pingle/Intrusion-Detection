"""
custom_queue.py

A custom implementation of a First-In, First-Out (FIFO) queue using a
linked list. This data structure is the core of the sliding window mechanism
used for efficient, time-based anomaly detection.
"""

class CustomQueue:
    """A robust, linked-list implementation of a FIFO queue."""

    class _Node:
        """A private inner class representing a node in the linked list."""
        def __init__(self, data):
            self.data = data
            self.next = None

    def __init__(self):
        """Initializes an empty queue."""
        self.front = None
        self.rear = None
        self._size = 0

    def enqueue(self, val):
        """Adds a value to the rear of the queue in O(1) time."""
        new_node = self._Node(val)
        if self.rear:
            self.rear.next = new_node
        else:
            # If the queue is empty, the new node is both front and rear
            self.front = new_node
        self.rear = new_node
        self._size += 1

    def dequeue(self):
        """
        Removes and returns the value from the front of the queue in O(1) time.

        Raises:
            IndexError: If the queue is empty.
        """
        if self.is_empty():
            raise IndexError("Cannot dequeue from an empty queue.")

        val = self.front.data
        self.front = self.front.next
        if not self.front:
            # If the queue becomes empty, the rear must also be None
            self.rear = None
        self._size -= 1
        return val

    def peek(self):
        """
        Returns the value at the front of the queue without removing it in O(1) time.

        Raises:
            IndexError: If the queue is empty.
        """
        if self.is_empty():
            raise IndexError("Cannot peek into an empty queue.")
        return self.front.data

    def is_empty(self) -> bool:
        """Returns True if the queue is empty, False otherwise."""
        return self._size == 0

    def __len__(self) -> int:
        """Allows using len(queue) to get the number of items in the queue."""
        return self._size

    def __iter__(self):
        """Returns an iterator to allow looping over the queue's items from front to rear."""
        current = self.front
        while current:
            yield current.data
            current = current.next