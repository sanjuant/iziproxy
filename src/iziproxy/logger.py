"""
Module utilitaire pour la gestion du logging dans IziProxy
"""

import logging
import sys


def get_logger(name, level=logging.INFO):
    """
    Configure et retourne un logger pour IziProxy
    
    Args:
        name (str): Nom du logger
        level (int): Niveau de log (par défaut: INFO)
        
    Returns:
        logging.Logger: Logger configuré
    """
    logger = logging.getLogger(name)
    
    # Ne pas reconfigurer si déjà configuré
    if logger.handlers:
        return logger
        
    logger.setLevel(level)
    
    # Configuration du handler de console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Format de log
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    
    # Ajout du handler au logger
    logger.addHandler(console_handler)
    
    return logger
