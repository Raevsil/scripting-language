import re
import logging
from collections import defaultdict, Counter
from pathlib import Path

# Признаки подозрительности
suspicious_keywords = ['admin', 'login', 'config']
suspicious_methods = ['PATCH', 'TRACE']
suspicious_user_agents = ['curl', 'Nmap', 'sqlmap']
long_parameter_threshold = 10

# Настройка логирования
logging.basicConfig(filename='suspicious_requests.log', level=logging.INFO, format='%(message)s')

def is_suspicious_request(request_line, user_agent):
    reasons = []
    parts = request_line.split()
    
    # Убедимся, что parts содержит ровно три элемента
    if len(parts) != 3:
        return reasons
    
    method, url, protocol = parts
    
    # Признак 1: подозрительные ключевые слова в URL
    if any(keyword in url for keyword in suspicious_keywords):
        reasons.append('suspicious_keyword_in_url')
    
    # Признак 2: длинные параметры в URL
    if '?' in url:
        params = url.split('?', 1)[1]
        if any(len(param) > long_parameter_threshold for param in params.split('&')):
            reasons.append('long_parameters_in_url')
    
    # Признак 3: подозрительные методы HTTP
    if method in suspicious_methods:
        reasons.append('suspicious_http_method')
    
    # Признак 4: подозрительные User-Agent
    if any(agent in user_agent for agent in suspicious_user_agents):
        reasons.append('suspicious_user_agent')
    
    return reasons

def analyze_log_file(log_file):
    suspicious_requests = defaultdict(list)
    
    with log_file.open('r') as file:
        for line in file:
            parts = line.split('"')
            if len(parts) > 5:
                request_line = parts[1]
                user_agent = parts[5]
                
                reasons = is_suspicious_request(request_line, user_agent)
                if len(reasons) >= 2:
                    suspicious_requests[line.strip()] = reasons
    
    return suspicious_requests

def main():
    # Указываем путь к лог-файлу
    log_file_path = Path('D:/access.log')
    
    suspicious_requests = analyze_log_file(log_file_path)
    
    # Определяем Top-20 подозрительных запросов
    top_suspicious_requests = Counter(suspicious_requests).most_common(20)
    
    # Выводим результаты в лог файл
    logging.info("Top-20 подозрительных запросов:")
    for request, reasons in top_suspicious_requests:
        logging.info(f"{request} - {', '.join(reasons)}")

if __name__ == "__main__":
    main()
