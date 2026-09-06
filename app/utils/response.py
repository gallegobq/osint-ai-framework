from fastapi.responses import JSONResponse


def success_response(
    data=None,
    message: str = "Success",
    status_code: int = 200,
):
    """
    Respuesta estándar para operaciones exitosas.
    """

    return JSONResponse(
        status_code=status_code,
        content={
            "success": True,
            "message": message,
            "data": data,
        },
    )


def created_response(
    data=None,
    message: str = "Created successfully.",
):
    """
    Respuesta estándar para creación de recursos.
    """

    return JSONResponse(
        status_code=201,
        content={
            "success": True,
            "message": message,
            "data": data,
        },
    )


def paginated_response(
    *,
    data,
    total: int,
    page: int,
    size: int,
    message: str = "Success",
):
    """
    Respuesta estándar para listas paginadas.
    """

    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": message,
            "data": data,
            "meta": {
                "total": total,
                "page": page,
                "size": size,
            },
        },
    )
