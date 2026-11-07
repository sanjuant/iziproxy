"""
Journalisation d'IziProxy.

Une bibliothèque ne doit pas imposer de sortie : par défaut aucun handler
n'est ajouté (les avertissements restent visibles grâce au handler de
dernier recours de Python, ou via la configuration de l'application).
Le mode débogage ajoute un handler sur stderr.
"""

import logging
import sys

LOGGER_NAME = "iziproxy"
_debug_handler = None


def get_logger(name=LOGGER_NAME, level=None):
    """
    Retourne le logger d'IziProxy.

    Args:
        name (str): Nom du logger
        level (int, optional): Niveau à appliquer

    Returns:
        logging.Logger: Logger
    """
    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(level)
    return logger


def enable_debug_logging():
    """Affiche tous les journaux d'IziProxy sur stderr."""
    global _debug_handler
    logger = logging.getLogger(LOGGER_NAME)
    if _debug_handler is None:
        _debug_handler = logging.StreamHandler(sys.stderr)
        _debug_handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(_debug_handler)
    _debug_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.debug("Debug logging enabled")


def disable_debug_logging():
    """Retire le handler de débogage et revient au niveau par défaut."""
    global _debug_handler
    logger = logging.getLogger(LOGGER_NAME)
    if _debug_handler is not None:
        logger.removeHandler(_debug_handler)
        _debug_handler = None
    logger.setLevel(logging.NOTSET)
