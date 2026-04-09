import time

class Timer:
    """Simple timer utility for tracking elapsed time."""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
    
    def start(self):
        """Start the timer."""
        self.start_time = time.time()
    
    def stop(self):
        """Stop the timer."""
        self.end_time = time.time()
    
    def elapsed(self):
        """
        Get elapsed time.
        
        Returns:
            float: Elapsed time in seconds
        """
        if self.start_time is None:
            return 0
        
        end_time = self.end_time if self.end_time is not None else time.time()
        return end_time - self.start_time
    
    def elapsed_formatted(self):
        """
        Get formatted elapsed time.
        
        Returns:
            str: Formatted time string (HH:MM:SS.mmm)
        """
        elapsed = self.elapsed()
        hours = int(elapsed // 3600)
        minutes = int((elapsed % 3600) // 60)
        seconds = elapsed % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:06.3f}"