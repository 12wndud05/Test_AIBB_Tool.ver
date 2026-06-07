# AIBB 공격자 박스 - AI 에이전트가 쉘을 열어 명령을 실행하는 격리 환경.
# 격리된 도커 네트워크에서 타겟만 공략하도록 사용한다(로컬 vulhub 전용).
FROM alpine:3.19

RUN apk add --no-cache \
    bash \
    curl \
    wget \
    nmap \
    netcat-openbsd \
    busybox-extras \
    python3 \
    bind-tools

# 컨테이너를 계속 띄워두고 docker exec 로 쉘 세션을 붙인다.
CMD ["sleep", "infinity"]
