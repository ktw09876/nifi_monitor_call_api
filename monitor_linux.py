import sys
import time
import warnings as wrn
import requests
import configparser as parser

from functools import reduce
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class NifiRestApiClient():
    def __init__(self):

        ###접속 정보 설정
        self.usernames, self.passwords, self.addr_ips, self.addr_ports = self.read_conf('settings/setting.ini')
        self.lin_token_path = 'settings/tokens' #토큰 경로 access_token.txt

        ###로그 경로
        self.lin_sys_diag = 'logs/system_diagnostics.txt' #윈도우/system-diagnostics 결과 로그 경로
        self.lin_flow_stat = 'logs/flow_status.txt' #/flow/status 결과 로그 경로
        self.lin_ctr_clst = 'logs/controller_cluster.txt' #/controller/cluster 결과 로그 경로
        self.lin_error_logs = 'logs/error_logs.txt' #nifi 서버 에러 로그 경로

        self.access_token = None
        self.first_token = False
        self.sys_diag_header = False
        self.ctr_clst_header = False
        self.flow_stat_header = False
        
    ###기본 설정값을 .ini에서 읽어옴
    def read_conf(self, ini_path: str) -> tuple:
        usernames = []
        passwords = []
        address_ips = []
        address_ports = []
        
        config = parser.ConfigParser()
        config.read(ini_path)

        for section in config.sections():
            usernames.append(config[section]['username'])
            passwords.append(config[section]['password'])
            address_ips.append(config[section]['ip'])
            address_ports.append(config[section]['port'])  

        return usernames, passwords, address_ips, address_ports

    ###입력 받은 json의 중첩을 해제, 평탄화
    def modify_json(self, data: dict, key: str = '') -> dict:
        items = []

        for k, v in data.items():
            if key:
                new_key = f'{key}.{k}'
            else:
                new_key = f'{k}'

            if isinstance(v, dict):
                items.extend(self.modify_json(v, new_key).items())

            elif isinstance(v, list):
                for i, item in enumerate(v):
                    items.extend(self.modify_json({f'{new_key}[{i}]': item}).items())

            else:
                items.append((k, v))

        return dict(items)

    ###데이터 출력 형식 지정 json -> tsv
    def transform_data_form(self, ip_in, port_in, data: dict) -> tuple:

        ###헤더 형식 변환
        data_headers = list(data.keys()) #호출로 반환 받은 json 데이터 중 키를 파싱, 리스트형태
        data_headers.insert(0, 'Time') #현재 시간
        data_headers.insert(1, 'address') # 노드 구분용 ip/ port
        tab_headers = '\t'.join(data_headers) #구분자 '\t' 을 이용해서 이어 붙임

        ###본문 데이터 형식 변환
        data_bodys = list(data.values()) #호출로 반환 받은 json 데이터 중 값을 파싱, 리스트형태

        ###값에 실수가 포함되어 있어서 타입 변환
        values = []
        for value in data_bodys:
            values.append(str(value))

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # 시간 기록

        values.insert(0, current_time) #현재 시간
        values.insert(1, f'{ip_in}:{port_in}') # 노드 구분용 ip/ port
        tab_bodys = '\t'.join(values) #구분자 '\t' 을 이용해서 이어 붙임

        return tab_headers, tab_bodys

    ###출력 결과 redirection
    def print_result(self, url: str, headers: tuple, bodys: tuple) -> None:

        #경로를 다르게 하기 위한 조건 검사
        if url == '/system-diagnostics':
            with open(self.lin_sys_diag, 'a') as result_logs: 
                if not self.sys_diag_header: #처음
                    result_logs.write(headers + '\n') #해더 작성
                    self.sys_diag_header = True
                result_logs.write(bodys + '\n') #바디 작성
        elif url == '/flow/status':
            with open(self.lin_flow_stat, 'a') as result_logs: 
                if not self.flow_stat_header:
                    result_logs.write(headers + '\n') 
                    self.flow_stat_header = True
                result_logs.write(bodys + '\n') 
        elif url == '/controller/cluster':
            with open(self.lin_ctr_clst, 'a') as result_logs: 
                if not self.ctr_clst_header:
                    result_logs.write(headers + '\n') 
                    self.ctr_clst_header = True
                result_logs.write(bodys + '\n') 

    ###입력 받은 인수 조건 검사
    def test_string(self, test_str: str) -> int:

        ###더하기
        if '+' in test_str: #인수에 '+'가 포함되어 있다면
            int_strs = list(map(int, test_str.split('+')))
            total = reduce(lambda x,y: x+y, int_strs)
            return total
        
        ###곱하기
        elif '*' in test_str: #인수에 '*'가 포함되어 있다면
            int_strs = list(map(int, test_str.split('*')))
            total = reduce(lambda x,y: x*y, int_strs)
            return total        
        
        ###그 외 문자열 인자를 바로 정수로 변환할 수 있는 경우
        else: 
            return int(test_str)
        
    ###새로운 토큰을 발급 받음
    def write_access_token(self, id_in: str, pwd_in: str, ip_in: str, port_in: str) -> None:
        _data = {
                'username': id_in,
                'password': pwd_in
        }
        response = requests.post(f'https://{ip_in}:{port_in}/nifi-api/access/token', data=_data, verify=False) #verify=False 보안에 대한 SSL 인증서 체크를 안 함

        ###파일에 토큰 저장
        with open(f'{self.lin_token_path}/access_token_{ip_in}:{port_in}.txt', 'w') as token:
            token.write(response.text)
            # print(self.access_token)    
    
    ###저장된 토큰 파일을 읽음
    def read_access_token(self, ip_in: str, port_in: str) -> None:
        with open(f'{self.lin_token_path}/access_token_{ip_in}:{port_in}.txt', 'r') as token: 
            self.access_token = token.read().rstrip() #파일을 윈도우에서 리눅스로 옮기는 경우 원치않는 개행문자가 추가되는 경우가 있음(\n), 개행문자 제거

    ###api 호출
    def get_info(self, id_catch: str, pwd_catch: str, ip_catch: str, port_catch: str, sub_url: str) -> None:

        ###api 호출에 필요한 인자 세팅
        if not self.first_token: #프로그램이 처음 시작할 때 
            self.write_access_token(id_catch, pwd_catch, ip_catch, port_catch) #토큰을 발급 받음
            self.first_token = True #처음 시작에만 토큰을 발급 받음, 이후에는 파일로 저장된 토큰을 활용
            print(f'Start new token setting {ip_catch}:{port_catch}')

        self.read_access_token(ip_catch, port_catch) #발급 받아 저장된 파일에서 토큰을 읽어옴
        _headers = { #api 호출에 필요한 인자
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        ###api 호출
        response = requests.get(f'https://{ip_catch}:{port_catch}/nifi-api{sub_url}', headers=_headers, verify=False) #api url

        try:

            ###api 호출에 성공하면 
            if response.status_code in (200, 201):
                raw_json = response.json() 
                # print(json_data, flush=True) #api 호출로 반환 받은 데이터 확인
                
                ###api 호출 시간 기록
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                mod_json = self.modify_json(raw_json) #json 의 중첩을 평탄화 한다
                trans_headers, trans_bodys = self.transform_data_form(ip_catch, port_catch, mod_json) #데이터 출력 형식 변환
                self.print_result(sub_url, trans_headers, trans_bodys)
                print(f'API call successful {ip_catch}:{port_catch}')
            
            ###호출에 실패한 이유가 토큰 인증 관련이라면
            elif response.status_code == 401:

                ### 에러 결과 redirection
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # 시간 기록
                with open(self.lin_error_logs, 'a') as error_logs: 
                    error_logs.write(f'{current_time} error_url: {sub_url}/{ip_catch}:{port_catch} response.code [{response.status_code}] {e}\n') # 형식: 2024-05-20 17:29:49 error_url: [url] response.code [401]
                
                print(f'Token error!!! resetting {ip_catch}:{port_catch}')
                self.write_access_token(id_catch, pwd_catch, ip_catch, port_catch) #새로운 토큰을 발급 받아서 
                self.read_access_token(ip_catch, port_catch) #다시 파일에서 토큰을 읽어옴
                _headers['Authorization'] = f'Bearer {self.access_token}' #새로 파일에서 읽어온 토큰을 인자로 할당

                ###다시 api 호출
                response = requests.get(f'https://{ip_catch}:{port_catch}/nifi-api{sub_url}', headers=_headers, verify=False) # api url

        ############### 테스트 필요 #########################################################
        ###그 외 다른 이유로 호출에 실패했다면
        except Exception as e:
            
            ### 에러 결과 redirection
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # 시간 기록
            with open(self.lin_error_logs, 'a') as error_logs: 
                error_logs.write(f'{current_time} error_url: {sub_url}/{ip_catch}:{port_catch} response.code [{response.status_code}] {e}\n') # 형식: 2024-05-20 17:29:49 error_url: [url] response.code [401]\
                
            print(f'API call failed!!! {ip_catch}:{port_catch}')
            raise Exception(f'error code[{response.status_code}] error url: {sub_url}/{ip_catch}:{port_catch}')

def main(term: str, end_time: str):
    cli = NifiRestApiClient() 
    
    ###입력 받은 인수 조건 검사
    try:    
        term_catch = cli.test_string(term)
        end_time_catch = cli.test_string(end_time)
    except ValueError as val_e:
        print(f'message {val_e}')
        sys.exit(1)

    ###입력 받는 인자를 주기로 api 호출   
    def call_apis_for_ip(username, password, ip, port):
        wrn.filterwarnings('ignore', message=f"Unverified HTTPS request is being made to host '{ip}'.*")
        cli.get_info(username, password, ip, port, '/system-diagnostics')
        cli.get_info(username, password, ip, port, '/controller/cluster')
        cli.get_info(username, password, ip, port, '/flow/status')

    ###시작 시간 기록
    start_time_recod = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'start_time: {start_time_recod}')

    ###호출 비동기 처리
    with ThreadPoolExecutor(max_workers=len(cli.addr_ips)) as executor:
        futures = []

        for _ in range(1, (end_time_catch + 1) // term_catch + 1):
            for id, pwd, ip, port in zip(cli.usernames, cli.passwords, cli.addr_ips, cli.addr_ports):
                futures.append(executor.submit(call_apis_for_ip, id, pwd, ip, port))

            time.sleep(term_catch)  # 호출 주기 조절

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f'Generated an exception: {e}')

    end_time_recod = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'end_time: {end_time_recod}')


if __name__ == '__main__':

    ###입력 받은 인수 조건 검사
    if len(sys.argv) == 3:

        ###명령행에 입력한 인자를 매개변수로 넘겨 받음
        main(sys.argv[1], sys.argv[2])
    else:
        print('error!!! Please enter the correct arguments python3 script.py term end_time')
    
