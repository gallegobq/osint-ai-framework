"""Servicios de aplicación.

Los consumidores importan cada servicio desde su módulo concreto. Mantener
este paquete libre de importaciones evita ciclos durante la composición de
dependencias HTTP y de workers.
"""
