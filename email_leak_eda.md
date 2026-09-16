# 이메일 기반 내부정보 유출 의심행위 탐색 분석

## 1. 실제 확인한 데이터 구조

SQLite/CSV 인벤토리는 `outputs/source_inventory.csv`에 기록했다. 분석 소스는 **sqlite (email)**이며 전체 1,314,400건 중 LDAP 사용자 ID와 등록 이메일이 동시에 일치한 815,250건을 발신 추정 이벤트로 사용했다. 원본은 수정하지 않았다.

## 2. 발신 추정 기준

`lower(trim(email.from)) = lower(trim(LDAP.email)) AND email.user = LDAP.user_id`만 인정했다. 수신자는 to/cc/bcc를 세미콜론으로 분리했고 정확히 `dtaa.com`인 도메인만 내부로 처리했다. 실제 주소·본문은 출력하지 않았다.

## 3. 식별된 의심 유형

외부 수신, 외부 첨부, 사용자 과거 대비 대용량, 복수 외부 대상, 외부 BCC, 비근무시간, 과거에 없던 수신자·도메인, 1시간 급증, 주별 반복, 3주 이상 장기 반복 및 복합신호를 다중 weak label로 생성했다. 이는 공격 또는 실제 유출의 정답 라벨이 아니다.

## 4. 유형별 건수와 비율

| label | count | rate_of_verified_events |
|---|---:|---:|
| NORMAL_OR_UNCLASSIFIED | 678,644 | 0.8324 |
| EXTERNAL_RECIPIENT | 136,519 | 0.1675 |
| LONG_TERM_EXTERNAL_TRANSFER | 128,053 | 0.1571 |
| ATTACHMENT_TO_EXTERNAL | 44,638 | 0.0548 |
| NEW_EXTERNAL_RECIPIENT | 32,150 | 0.0394 |
| MULTI_SIGNAL_HIGH_RISK | 26,997 | 0.0331 |
| REPEATED_EXTERNAL_TRANSFER | 17,189 | 0.0211 |
| MULTIPLE_EXTERNAL_RECIPIENTS | 11,907 | 0.0146 |
| OFF_HOURS_EXTERNAL_SEND | 8,500 | 0.0104 |
| NEW_EXTERNAL_DOMAIN | 3,516 | 0.0043 |
| BURST_EXTERNAL_SEND | 194 | 0.0002 |
| LARGE_MESSAGE_TO_EXTERNAL | 87 | 0.0001 |

복수 수신자 탐색/운영/고위험 기준은 각각 2/2/3명이다. 실제 분포 분위수에서 정했다.

## 5. NIA 유사 장기 반복 후보

`LONG_TERM_EXTERNAL_TRANSFER` 후보 이벤트는 128,053건이다. 여러 주에 걸친 외부 전송 지속성을 나타낼 뿐, 비공개 자료 유출을 확인하지 않는다.

## 6. 익명화된 고위험 사례

상위 100건은 `outputs/high_risk_cases_masked.csv`에 사용자 해시, 집계 특성, label/reason code만 저장했다. 이메일 주소·도메인 원문·content는 포함하지 않았다.

## 7. 한계와 오탐 가능성

외부 협력, 대량 배포, 야간 근무, 정기 보고도 같은 신호를 만든다. size 단위와 발송 방향은 원천 명세가 없고, 신규성의 초기 구간은 cold start다. 알려진 정답이 없으므로 precision/recall/accuracy는 계산하지 않았다.

## 8. 실제 유출 확인에 필요한 데이터

메일 게이트웨이 방향/전달 상태, 첨부 파일명·해시·크기·분류등급, DLP 판정, 승인된 협력사 allowlist, 휴가·근무표, 케이스 조사 결과와 CERT answer key가 필요하다.

## 9. SIEM/ML 발전 방향

SIEM은 발신자 검증 후 복합 조건과 reason code를 경보로 전송하고, 사용자·부서·협력사별 예외를 적용한다. ML은 시간순 분할, 과거 전용 특징, analyst-reviewed 라벨을 사용하며 calibration과 비용 기반 임계값을 운영 환경에서 검증해야 한다.

## 10. 사용자×일자 위험상태 라벨

핵심 분석 단위는 사용자×일자이며 위험등급 분포는 `{'GENERAL': 275277, 'HIGH': 12243, 'CAUTION': 1402, 'CRITICAL': 861}`이다. 위험점수는 RI-01(비정상 시간), RI-03(폭증), RI-06(외부 첨부·크기)와 사용 가능한 S3 순서점수만 재정규화했다. Isolation Forest를 실행하지 않았으므로 `anomaly_score`와 `risk_score_full`은 결측으로 보존했다. `score_confidence`는 특징 가용성·기준선 성숙도·소스 품질만 반영하여 위험점수와 분리했다.

## 11. 사용자 전체기간 조사 우선순위

전체기간 요약의 우선순위 분포는 `{'P2_PRIORITY_REVIEW': 644, 'P1_IMMEDIATE_REVIEW': 353, 'P3_MONITOR': 3}`이다. 이는 최고 위험일 복사가 아니라 최근 30일 평균, 고위험 일수, 반복 주수, 장기 지속성과 S3 완성 횟수를 함께 반영한 조사 우선순위다.

## 12. S3 이메일 반출 의심 시나리오

파일 활동 급증 뒤 2시간 이내 외부 첨부메일이 발생하고 크기 또는 첨부 수 증가까지 관찰된 `S3_COMPLETED` 사용자×일 후보는 95건이다. 단일 이메일 이벤트에는 완료 상태를 부여하지 않았고, 파일 이벤트가 선행하는 후보만 저장했다.

## 13. 정답 라벨과 weak label의 차이

이벤트 라벨, 사용자×일 위험상태, 전체기간 우선순위 모두 행동 로그에서 계산한 weak label이다. 어떤 사용자도 공격자·내부자 위협 행위자·정보 유출자로 확정하지 않는다. 정확도 평가는 보안 담당자 표본 검토 또는 별도 정답 데이터가 있어야 가능하다.
