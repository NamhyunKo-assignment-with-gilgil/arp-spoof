# ARP Spoof 프로젝트

## arp-spoof 실행 영상

[arp-spoof 영상](https://youtu.be/mfeJhtpn5fI)

## 과제 설명

https://gitlab.com/gilgil/sns/-/wikis/arp-spoofing/arp-spoofing

https://gitlab.com/gilgil/sns/-/wikis/arp-spoofing/report-arp-spoof

- sender에서 보내는 spoofed IP packet을 attacker가 수신하면 이를 relay하는 것 코드를 구현
- sender에서 infect가 풀리는(recover가 되는) 시점을 정확히 파악하여 재감염시키는 코드를 구현
- (sender, target) flow를 여러개 처리할 수 있도록 코드를 구현

## 공부 내용

### c++ Map

- MAP 자료구조 이용
    
    (참고자료 : http://devlab.neonkid.xyz/2019/08/09/c++/2019-08-09-C-Map/)
    

### ARP Spoofing 공격 원리

- spoof 패킷과 relay 패킷 구분해서 흐름 제어
- (참고자료 : https://gitlab.com/gilgil/sns/-/wikis/arp-spoofing/arp-spoofing)

## 소스 코드 설명

### main.cpp

- `main()` 함수
    - arp 스푸핑을 위한 전체 흐름 제어
        - 실행 인자 받아서 sender, target 구분 및 쌍 저장
        - pcap으로 패킷 전송 및 수신 준비
        - 자기 자신 mac과 ip 주소 찾기
    - `send_arp_preparing` 함수 호출
        - arp table 감염을 위한 준비
    - arp spoofing 무한 반복
        - `arp_infection` 함수 호출
            - arp table 실제 감염
        - `send_relay_packet` 함수 호출
            - spoof 패킷 수신 후 relay 패킷으로 변조 후 전송
        - **arp table 재검사 시 재감염 시키기**
- `arp_infection` 함수
    - 위조된 ARP Reply 패킷을 생성하여 전송
    - sender IP에 대해 공격자의 MAC 주소를 target IP(게이트웨이)로 속이는 패킷을 만들어 감염시킴
    - 공격 대상의 ARP 테이블을 조작하여 패킷이 공격자를 거쳐가도록 유도하는 역할
- `send_relay_packet` 함수
    - 중간자 공격에서 가로챈 패킷을 실제 목적지로 중계하는 함수
    - 원본 패킷의 이더넷 헤더를 수정하여 목적지 MAC을 실제 타겟으로, 소스 MAC을 공격자로 변경
    - 네트워크 연결이 끊어지지 않도록 패킷을 정상적으로 전달하여 공격을 은밀하게 유지

### **ethhdr.cpp**

- `stringmac_to_bytemac()` 함수
    - 문자열 형태의 MAC 주소를 바이트 배열로 변환
    - "AA:BB:CC:DD:EE:FF" 형식을 6바이트 배열로 파싱
    - sscanf를 이용해 16진수 문자열을 바이트로 변환
- `bytemac_to_stringmac()` 함수
    - 바이트 배열 형태의 MAC 주소를 문자열로 변환
    - 6바이트 배열을 "AA:BB:CC:DD:EE:FF" 형식으로 출력
    - sprintf를 이용해 바이트를 16진수 문자열로 변환

### **arphdr.cpp**

- `stringip_to_byteip()` 함수
    - 문자열 형태의 IP 주소를 32비트 정수로 변환
    - "192.168.1.1" 형식을 네트워크 바이트 순서로 변환
    - 각 옥텟을 적절한 위치로 시프트하여 조합
- `byteip_to_stringip()` 함수
    - 32비트 정수 형태의 IP 주소를 문자열로 변환
    - 네트워크 바이트 순서에서 "192.168.1.1" 형식으로 변환
    - 비트 마스킹과 시프트 연산을 이용해 각 값 추출