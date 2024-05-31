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
        self.usernames, self.passwords, self.address_ips, self.address_ports = self.read_conf('settings/setting.ini')
        self.lin_token_path = 'settings/tokens/access_token' #토큰 경로

        ###로그 경로
        self.lin_sys_diag = 'logs/system-diagnostics.txt' #/system-diagnostics 결과 로그 경로
        self.lin_flow_stat = 'logs/flow_status.txt' #/flow/status 결과 로그 경로
        self.lin_ctr_clst = 'logs/controller_cluster.txt' #/controller/cluster 결과 로그 경로
        self.lin_error_logs = 'logs/error_logs.txt' #에러 로그 경로

        self.access_token = None
        self.sys_diag_header = False
        self.ctr_clst_header = False
        self.flow_stat_header = False
        
    ###기본 설정값을 .ini에서 읽어옴
    def read_conf(self, ini_path: str) -> tuple:
        usernames = []
        passwords = []
        address_ids = []
        address_ports = []
        
        config = parser.ConfigParser()
        config.read(ini_path)

        for section in config.sections():
            usernames.append(config[section]['username'])
            passwords.append(config[section]['password'])
            address_ids.append(config[section]['ip'])
            address_ports.append(config[section]['port'])  

        return usernames, passwords, address_ids, address_ports

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
    def transform_data_form(self, in_ip, in_port, data: dict) -> tuple:

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
        values.insert(1, f'{in_ip}:{in_port}') # 노드 구분용 ip/ port
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
    def write_access_token(self, in_id: str, in_pwd: str, in_ip: str, in_port: str) -> None:
        _data = {
                'username': in_id,
                'password': in_pwd
        }
        response = requests.post(f'https://{in_ip}:{in_port}/nifi-api/access/token', data=_data, verify=False) #verify=False 보안에 대한 SSL 인증서 체크를 안 함

        ###파일에 토큰 저장
        with open(self.lin_token_path, 'w') as access_token:
            access_token.write(response.text)
            # print(self.access_token)    
    
    ###저장된 토큰 파일을 읽음
    def read_access_token(self) -> None:
        with open(self.lin_token_path, 'r') as access_token: 
            self.access_token = access_token.read().rstrip() #파일을 윈도우에서 리눅스로 옮기는 경우 원치않는 개행문자가 추가되는 경우가 있음(\n), 개행문자 제거

    ###api 호출
    def get_info(self, catch_id: str, catch_pwd: str, catch_ip: str, catch_port: str, sub_url: str) -> str:

        ###api 호출에 필요한 인자 세팅
        self.read_access_token() #파일에서 토큰을 읽어옴
        _headers = { #api 호출에 필요한 인자
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }

        ###api 호출
        response = requests.get(f'https://{catch_ip}:{catch_port}/nifi-api{sub_url}', headers=_headers, verify=False) #api url

        ###api 호출에 성공하면 
        try:
            if response.status_code in (200, 201):
                raw_json = response.json() 
                controllerStatus = raw_json
                # print(json_data, flush=True) #api 호출로 반환 받은 데이터 확인
                
                ###api 호출 시간 기록
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                mod_json = self.modify_json(controllerStatus) #json 의 중첩을 평탄화 한다
                trans_headers, trans_bodys = self.transform_data_form(catch_ip, catch_port, mod_json) #데이터 출력 형식 변환
                self.print_result(sub_url, trans_headers, trans_bodys)
            
            ###호출에 실패한 이유가 토큰 인증 관련이라면
            elif response.status_code == 401:
                self.write_access_token(catch_id, catch_pwd, catch_ip, catch_port) #새로운 토큰을 발급 받아서 
                self.read_access_token() #다시 파일에서 토큰을 읽어옴
                _headers['Authorization'] = f'Bearer {self.access_token}' #새로 파일에서 읽어온 토큰을 인자로 할당

                ###다시 api 호출
                response = requests.get(f'https://{catch_ip}:{catch_port}/nifi-api{sub_url}', headers=_headers, verify=False) # api url

        ############### 테스트 필요 #########################################################
        ###그 외 다른 이유로 호출에 실패했다면
        except requests.exceptions.RequestException as req_e:
            
            ### 에러 결과 redirection
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # 시간 기록
            with open(self.lin_error_logs, 'a') as error_logs: 
                error_logs.write(f'{current_time} error: url: {sub_url} response.code [{response.status_code}] {req_e}\n') # 형식: 2024-05-20 17:29:49 error: response.code [401]

            raise Exception(f'error code[{response.status_code}] error url: {sub_url}')

def main(term: str, end_time: str):
    cli = NifiRestApiClient() 

    ###입력 받은 인수 조건 검사
    try:    
        catch_term = cli.test_string(term)
        catch_end_time = cli.test_string(end_time)
    except ValueError as val_e:
        print(f'message {val_e}')

        sys.exit(1)
    
    ###시작 시간 기록
    start_time_recod = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'start_time: {start_time_recod}')

    ###입력 받는 인자를 주기로 api 호출   
    def call_apis_for_ip(ip, port, username, password):
        wrn.filterwarnings('ignore', message=f"Unverified HTTPS request is being made to host '{ip}'.*")
        cli.get_info(username, password, ip, port, f'/system-diagnostics')
        cli.get_info(username, password, ip, port, f'/controller/cluster')
        cli.get_info(username, password, ip, port, f'/flow/status')

    ###호출 비동기 처리
    with ThreadPoolExecutor(max_workers=len(cli.address_ips)) as executor: #동시에 여러 쓰레드로 작업 진행, max_workers는 최대 쓰레드 개수
        futures = []
        for _ in range(1, (catch_end_time + 1) // catch_term + 1):
            for username, password, ip, port in zip(cli.usernames, cli.passwords, cli.address_ips, cli.address_ports):
                futures.append(executor.submit(call_apis_for_ip, ip, port, username, password)) #call_apis_for_ip() 에 ip, port, username, password 전달
            time.sleep(catch_term)  # 호출 주기 조절

        for future in as_completed(futures): #futures 내의 모든 객체들이 완료되길 기다렸다가 완료되는 순서대로 반환
            try:
                future.result()
            except Exception as e:
                print(f'Generated an exception: {e}')

    ###종료 시간 기록
    end_time_recod = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'end_time: {end_time_recod}')


if __name__ == '__main__':

    ###입력 받은 인수 조건 검사
    if len(sys.argv) == 3:

        ###명령행에 입력한 인자를 매개변수로 넘겨 받음
        main(sys.argv[1], sys.argv[2])
    else:
        print('error!!! Please enter the correct arguments python3 script.py term end_time')
    
