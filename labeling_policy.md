# 이메일 유출 의심행위 weak-label 정책

모든 라벨은 `sender_verified=true` 이벤트에만 적용한다. 외부 주소 존재만으로 악성을 확정하지 않는다.

| 라벨명 | 분석 단위 | 탐지 조건 | 사용 컬럼 | 임계값 | 선정 근거 | 오탐 가능성 | 미탐 가능성 | 실제 유출 확정 | NIA 관련성 |
|---|---|---|---|---|---|---|---|---|---|
| NORMAL_OR_UNCLASSIFIED | 이벤트 | 현 규칙 신호 없음 | 전체 파생변수 | 없음 | 배타적 기본값 | 미정의 위험 포함 | 규칙 밖 행위 | 아니오 | 낮음 |
| EXTERNAL_RECIPIENT | 이벤트 | 외부 수신자 1+ | 수신자 도메인 | 1 | 탐색용 기본 신호 | 정상 협력 | 내부 주소 오분류 | 아니오 | 중간 |
| ATTACHMENT_TO_EXTERNAL | 이벤트 | 외부+첨부 | attachment_count | 1+ | 직접 관찰 | 정상 자료 공유 | 링크 공유 | 아니오 | 높음 |
| LARGE_MESSAGE_TO_EXTERNAL | 이벤트 | 사용자 과거 대비 큼 | message_size | 과거 200건 p99 또는 median+6*MAD | 강건 기준선 | 정상 대용량 | 압축·링크 | 아니오 | 높음 |
| MULTIPLE_EXTERNAL_RECIPIENTS | 이벤트 | 복수 주소/도메인 | 외부 수신자·도메인 수 | outputs/thresholds.json | 실제 분위수 | 배포 메일 | 소수 대상 반복 | 아니오 | 중간 |
| BCC_TO_EXTERNAL | 이벤트 | 외부 BCC 1+ | bcc | 1 | 직접 관찰 | 정상 BCC | 숨김 없는 행위 | 아니오 | 중간 |
| OFF_HOURS_EXTERNAL_SEND | 이벤트 | 주말 또는 평일 08~19시 외 | date | 고정 초기 기준 | 요구사항 | 교대·재택 | 근무시간 내 행위 | 아니오 | 중간 |
| NEW_EXTERNAL_RECIPIENT | 이벤트 | 과거에 없던 외부 주소 | 과거 수신자 집합 | cold start 제외 | 미래 누출 없는 순차 계산 | 신규 협력사 | 기존 대상 악용 | 아니오 | 중간 |
| NEW_EXTERNAL_DOMAIN | 이벤트 | 과거에 없던 외부 도메인 | 과거 도메인 집합 | cold start 제외 | 미래 누출 없는 순차 계산 | 신규 협력사 | 기존 도메인 악용 | 아니오 | 중간 |
| BURST_EXTERNAL_SEND | 이벤트 | 1시간 외부메일 5+ | 시각 이력 | 5 | 운영 초기값, 튜닝 필요 | 업무 집중 | 저속 전송 | 아니오 | 중간 |
| REPEATED_EXTERNAL_TRANSFER | 이벤트 | 주간 외부메일 5+ | 주별 이력 | 5 | 운영 초기값, 튜닝 필요 | 정기 보고 | 더 낮은 빈도 | 아니오 | 높음 |
| LONG_TERM_EXTERNAL_TRANSFER | 이벤트 | 3개 선행 주 이상 외부 활동 | 주별 이력 | 3주, 21일 | NIA 장기 반복 대응 | 장기 협업 | 간헐적 행위 | 아니오 | 매우 높음 |
| MULTI_SIGNAL_HIGH_RISK | 이벤트 | 기본 외부 외 신호 3+ | 라벨 집합 | 3 | 단일 신호 고위험 방지 | 복합 정상업무 | 은밀한 단일 신호 | 아니오 | 높음 |

Email Risk Score는 각 근거점수의 최대값 전액과 나머지의 65%를 합쳐 100으로 제한한다. LOW 0–24, MEDIUM 25–49, HIGH 50–74, CRITICAL 75–100이며 모든 점수에 `reason_codes`를 보존한다. 보안 담당자 표본 검토 또는 별도 정답 없이는 정확도를 주장하지 않는다.
