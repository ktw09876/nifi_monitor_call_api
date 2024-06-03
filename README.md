# NiFi_monitoring_call_api
- NiFi의 전체 노드에서
1. 사용중인 메모리 량
2. 쓰레드 개수
3. 초당 처리한 데이터 량  
등을 확인하기 위한 방법으로 관련 api를 호출

- test환경 setting  
-- Nifi: 1.21.0  
-- java: openjdk version "11"  
-- 내장 주키퍼  
-- 2개노드로 클러스팅  
    - VMware 를 이용해 가상환경 구성
    - OS: Rocky Linux9  
    - HDD: 20GB
    - RAM: 2G

1. /nifi-api/system-diagnostics
2. /nifi-api/controller/cluster
3. /nifi-api/flow/status  
- 3개의 api로 test
- NiFi 계정 정보로 토큰을 발급 받아 사용
- nifi.properties에서 토큰 유효기간을 조절하려 했으나 실패  
-->토큰이 만료될때마다 새로 발급 받아서 call 했음(약 8시간)
