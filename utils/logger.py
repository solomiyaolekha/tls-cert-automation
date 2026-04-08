import logging

def setup_logger():
    logger = logging.getLogger("CertTool")
    logger.setLevel(logging.INFO)
    
    # Формат запису: Час - Рівень - Повідомлення
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Запис у файл
    file_handler = logging.FileHandler("app.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    
    # Вивід у консоль
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger