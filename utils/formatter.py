class Formatter:
    """Utility for formatting output messages with colors and styles."""
    
    # ANSI color codes
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'purple': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'bold': '\033[1m',
        'underline': '\033[4m',
        'end': '\033[0m'
    }
    
    # Windows-compatible symbols
    SYMBOLS = {
        'success': '[+]',
        'error': '[-]',
        'warning': '[~]',
        'info': '[*]'
    }
    
    @classmethod
    def format_text(cls, text, color=None, bold=False, underline=False):
        """
        Format text with ANSI color codes.
        
        Args:
            text (str): Text to format
            color (str): Color name (red, green, yellow, blue, purple, cyan, white)
            bold (bool): Whether to make text bold
            underline (bool): Whether to underline text
            
        Returns:
            str: Formatted text
        """
        formatted = ''
        if color and color in cls.COLORS:
            formatted += cls.COLORS[color]
        if bold:
            formatted += cls.COLORS['bold']
        if underline:
            formatted += cls.COLORS['underline']
        
        formatted += text
        formatted += cls.COLORS['end']
        return formatted
    
    @classmethod
    def print_success(cls, text):
        """Print success message in green."""
        print(cls.format_text(text, 'green', bold=True))
    
    @classmethod
    def print_error(cls, text):
        """Print error message in red."""
        print(cls.format_text(text, 'red', bold=True))
    
    @classmethod
    def print_warning(cls, text):
        """Print warning message in yellow."""
        print(cls.format_text(text, 'yellow', bold=True))
    
    @classmethod
    def print_info(cls, text):
        """Print info message in blue."""
        print(cls.format_text(text, 'blue', bold=True))