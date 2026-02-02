# -*- coding: utf-8 -*-
import logging
import sys
import subprocess

_logger = logging.getLogger(__name__)


def _install_dependencies():
    """Instala dependências Python necessárias se não estiverem presentes."""
    packages_map = {
        'websockets': 'websockets',
    }
    missing = []
    
    for pip_pkg, import_name in packages_map.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_pkg)
    
    if missing:
        _logger.info(f"Instalando dependências: {', '.join(missing)}")
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install'] + missing,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            _logger.info(f"Dependências instaladas com sucesso")
        except Exception as e:
            _logger.error(f"Erro ao instalar dependências: {e}")


_install_dependencies()

from . import models
from . import controllers
