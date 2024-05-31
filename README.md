# NiFi_monitoring_call_api
- NiFi의 전체 노드에서
1. 사용중인 메모리 량
2. 쓰레드 개수
3. 초당 처리한 데이터 량  
등을 확인하기 위한 방법으로 관련 api를 호출

- test환경 setting  
-- Nifi: 1.21.0  
-- java: openjdk version "11"  
-- 2개노드로 클러스팅  
-- 내장 주키퍼

1. /nifi-api/system-diagnostics
2. /nifi-api/controller/cluster
3. /nifi-api/flow/status  
- 3개의 api로 test