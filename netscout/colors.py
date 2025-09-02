"""
Neon color schemes and terminal styling for NetScout.

This module provides vibrant, hacker-style color schemes for terminal output.
"""

import sys
import os
from typing import Optional


class NeonColors:
    """Neon color palette with cyberpunk aesthetics"""
    
    # Reset
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Neon Colors (Bright versions)
    NEON_GREEN = '\033[92m'       # Bright Green - Matrix style
    NEON_CYAN = '\033[96m'        # Bright Cyan - Tron style  
    NEON_MAGENTA = '\033[95m'     # Bright Magenta - Synthwave
    NEON_YELLOW = '\033[93m'      # Bright Yellow - Electric
    NEON_RED = '\033[91m'         # Bright Red - Alert
    NEON_BLUE = '\033[94m'        # Bright Blue - Ice
    NEON_WHITE = '\033[97m'       # Bright White - Pure
    NEON_ORANGE = '\033[38;5;208m' # Orange 256-color
    NEON_PINK = '\033[38;5;198m'   # Hot Pink 256-color
    NEON_PURPLE = '\033[38;5;129m' # Purple 256-color
    
    # Background Neon Colors
    BG_NEON_GREEN = '\033[102m'
    BG_NEON_CYAN = '\033[106m'
    BG_NEON_MAGENTA = '\033[105m'
    BG_NEON_YELLOW = '\033[103m'
    BG_NEON_RED = '\033[101m'
    BG_NEON_BLUE = '\033[104m'
    
    # Dark backgrounds for contrast
    BG_DARK = '\033[40m'          # Black
    BG_GRAY = '\033[100m'         # Dark Gray
    
    # Special effects
    RAINBOW_COLORS = [
        NEON_RED, NEON_ORANGE, NEON_YELLOW, 
        NEON_GREEN, NEON_CYAN, NEON_BLUE, 
        NEON_PURPLE, NEON_MAGENTA, NEON_PINK
    ]


class ColorScheme:
    """Color scheme for different types of output"""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and self._supports_color()
    
    @staticmethod
    def _supports_color() -> bool:
        """Check if terminal supports color output"""
        return (
            hasattr(sys.stdout, "isatty") and 
            sys.stdout.isatty() and 
            sys.platform != "win32"  # Basic Windows check
        ) or "FORCE_COLOR" in os.environ
    
    def colorize(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled"""
        if not self.enabled:
            return text
        return f"{color}{text}{NeonColors.RESET}"
    
    # Semantic color methods
    def success(self, text: str) -> str:
        """Green for success messages"""
        return self.colorize(text, NeonColors.NEON_GREEN + NeonColors.BOLD)
    
    def warning(self, text: str) -> str:
        """Yellow for warnings"""
        return self.colorize(text, NeonColors.NEON_YELLOW + NeonColors.BOLD)
    
    def error(self, text: str) -> str:
        """Red for errors"""
        return self.colorize(text, NeonColors.NEON_RED + NeonColors.BOLD)
    
    def info(self, text: str) -> str:
        """Cyan for information"""
        return self.colorize(text, NeonColors.NEON_CYAN)
    
    def highlight(self, text: str) -> str:
        """Magenta for highlights"""
        return self.colorize(text, NeonColors.NEON_MAGENTA + NeonColors.BOLD)
    
    def dim(self, text: str) -> str:
        """Dimmed text"""
        return self.colorize(text, NeonColors.DIM)
    
    def title(self, text: str) -> str:
        """White bold for titles"""
        return self.colorize(text, NeonColors.NEON_WHITE + NeonColors.BOLD)
    
    def stat_number(self, text: str) -> str:
        """Neon pink for numbers/statistics"""
        return self.colorize(text, NeonColors.NEON_PINK + NeonColors.BOLD)
    
    def url(self, text: str) -> str:
        """Blue for URLs"""
        return self.colorize(text, NeonColors.NEON_BLUE + NeonColors.UNDERLINE)
    
    def file_path(self, text: str) -> str:
        """Purple for file paths"""
        return self.colorize(text, NeonColors.NEON_PURPLE)
    
    def domain_name(self, text: str) -> str:
        """Orange for domain names"""
        return self.colorize(text, NeonColors.NEON_ORANGE)
    
    def ip_address(self, text: str) -> str:
        """Green for IP addresses"""
        return self.colorize(text, NeonColors.NEON_GREEN)
    
    def asn_number(self, text: str) -> str:
        """Cyan for ASN numbers"""
        return self.colorize(text, NeonColors.NEON_CYAN)
    
    def progress_bar(self, text: str) -> str:
        """Animated-style progress indicators"""
        return self.colorize(text, NeonColors.NEON_YELLOW + NeonColors.BOLD)
    
    def rainbow_text(self, text: str) -> str:
        """Apply rainbow colors to text"""
        if not self.enabled:
            return text
        
        result = []
        colors = NeonColors.RAINBOW_COLORS
        for i, char in enumerate(text):
            color = colors[i % len(colors)]
            result.append(f"{color}{char}")
        result.append(NeonColors.RESET)
        return ''.join(result)
    
    def neon_box(self, text: str, color: str = None) -> str:
        """Create a neon-style box around text"""
        if color is None:
            color = NeonColors.NEON_CYAN
        
        lines = text.split('\n')
        max_width = max(len(line) for line in lines) if lines else 0
        
        # Box characters
        top_line = "╔" + "═" * (max_width + 2) + "╗"
        bottom_line = "╚" + "═" * (max_width + 2) + "╝"
        
        result = [self.colorize(top_line, color + NeonColors.BOLD)]
        
        for line in lines:
            padded_line = f" {line.ljust(max_width)} "
            boxed_line = "║" + padded_line + "║"
            result.append(self.colorize("║", color + NeonColors.BOLD) + 
                         self.colorize(padded_line, NeonColors.NEON_WHITE) + 
                         self.colorize("║", color + NeonColors.BOLD))
        
        result.append(self.colorize(bottom_line, color + NeonColors.BOLD))
        return '\n'.join(result)
    
    def gradient_text(self, text: str, start_color: str, end_color: str) -> str:
        """Create gradient effect (simplified version)"""
        if not self.enabled or len(text) <= 1:
            return self.colorize(text, start_color)
        
        # Simple gradient - alternate between start and end colors
        result = []
        for i, char in enumerate(text):
            if i < len(text) // 2:
                color = start_color
            else:
                color = end_color
            result.append(f"{color}{char}")
        result.append(NeonColors.RESET)
        return ''.join(result)


def create_ascii_banner() -> str:
    """Create ASCII art banner for NetScout"""
    banner = r"""
    ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
    ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
    ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
                                                                           
         🌐 Network Discovery & ASN Intelligence Platform 🌐              
    """
    return banner.strip()


def create_progress_spinner() -> list:
    """Create animated spinner frames"""
    return [
        "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
    ]


def create_neon_separators() -> dict:
    """Create various neon-style separators"""
    return {
        'thick': "━" * 60,
        'double': "═" * 60,
        'wave': "～" * 60,
        'dots': "·" * 60,
        'stars': "✦" * 30,
        'arrows': "→" * 30,
        'dashes': "⚡" * 30,
    }


# Global color scheme instance
_color_scheme = None


def get_color_scheme(enabled: Optional[bool] = None) -> ColorScheme:
    """Get global color scheme instance"""
    global _color_scheme
    if _color_scheme is None or enabled is not None:
        _color_scheme = ColorScheme(enabled if enabled is not None else True)
    return _color_scheme


# Convenience functions
def success(text: str) -> str:
    return get_color_scheme().success(text)


def warning(text: str) -> str:
    return get_color_scheme().warning(text)


def error(text: str) -> str:
    return get_color_scheme().error(text)


def info(text: str) -> str:
    return get_color_scheme().info(text)


def highlight(text: str) -> str:
    return get_color_scheme().highlight(text)


def stat_number(text: str) -> str:
    return get_color_scheme().stat_number(text)


def rainbow_text(text: str) -> str:
    return get_color_scheme().rainbow_text(text)


def neon_box(text: str, color: str = None) -> str:
    return get_color_scheme().neon_box(text, color)