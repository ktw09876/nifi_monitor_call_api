# NiFi_monitoring_call_api
- 멀티노드 환경에서 각 노드 별로 api를 비동기 호출, 각각의 관련 데이터를 .txt로 저장하는 스크립트
- 고객사의 요청으로 NiFi의 전체 노드에서
    1. 사용중인 메모리 량
    2. 쓰레드 개수
    3. 초당 처리한 데이터 량  
등을 확인하기 위한 방법으로 관련 api를 호출

- test환경 setting  
-- Python 3.7.16  
-- Nifi: 1.21.0  
-- java: openjdk version "11"  
-- 내장 주키퍼  
-- 3개 노드로 클러스팅  
    - VMware 를 이용해 가상환경 구성
    - OS: Rocky Linux9  
    - HDD: 20GB
    - RAM: 4G

1. /nifi-api/system-diagnostics
2. /nifi-api/controller/cluster
3. /nifi-api/flow/status  
- 3개의 api로 test
- NiFi 계정 정보로 토큰을 발급 받아 사용

## 어려웠던 점  
1. nifi 서버는 linux, 개발환경은 윈도우 vscode, 개발한 스크립트를 리눅스에서 테스트하는 과정에서
윈도우에 저장된 토큰을 리눅스로 옮겨서 실행  
    --> 토큰의 마지막에 의도하지 않은 개행문자(\n)가 추가됨  
    : 윈도우에 있는 토큰을 사용하지 않고 토큰을 발급 받아 저장하도록 스크립트 수정
2. ecal()
    - 매개변수로 받은 식을 문자열로 받아서 실행하는 함수
    - 사용자에게 입력 받은 시간 인수(60*2/ 2+5) 등을 실행하기 위해 사용했지만
        1. 디버깅이 어렵다
        2. 보안의 위험성이 있다  
        의 이유로 인자를 조건 검사하는 로직으로 대체 
3. SSL 인증 
    - 해당 사이트를 인증해서 진행하려 했으나 실패  
    --> 선임의 도움으로 토큰을 이용해 인증 받을 수 있음을 알게 됨
    - 토큰을 발급받았지만 유효기간이 있음을 알게 됨
    - nifi.properties에서 토큰 유효기간을 조절하려 했으나 실패  
    -->토큰이 만료될때마다 새로 발급 받아서(약 8시간) 호출 했음
4. 멀티 노드 환경 구성을 위해 Clustering
    - VMware를 이용해 3개의 가상 환경 구축
    - 옵션 설정이 어려웠음(3일 걸림)
        1. nifi.properties
        2. zookeeper.properties
        3. state-management.xml
        4. /etc/hosts
        5. 지정된 각각의 호스트에 ID를 부여
        6. https 설정(인증키)
        7. 방화벽 포트번호


