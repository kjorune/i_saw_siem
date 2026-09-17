# 이메일 외부 유출 위험 사용자 탐지를 위한 Sigma 룰 및 모델 개발 적용 가이드

작성 기준일: 2026-09-15  
검토 대상: `테이렌_이메일_외부유출_위험사용자탐지_프로젝트_기획안_초안.md`, `샘플데이터.db`, `email_leak_analysis` 산출물 및 사용자 제공 GPT 답변

## 1. 결론

현재 프로젝트에 Sigma의 **규칙 구조와 상관분석 개념은 적용할 수 있다.** 다만 샘플은 Windows Event Log가 아니라 CERT 계열의 이메일·파일·웹·장치·로그온 행위 데이터이므로, GPT 답변에 제시된 `EventID=4625`, PowerShell, 관리자 그룹 변경 등의 공개 SigmaHQ 룰은 현재 데이터에 직접 실행할 수 없다.

현 단계의 권장 구조는 다음과 같다.

| 계층 | 역할 | 현재 샘플 적용 여부 | 모델에서의 용도 |
|---|---|---:|---|
| 1. 행동 기준선 | 사용자 자신의 과거와 비교해 크기·빈도·시간·대상 신규성을 측정 | 가능 | 모델 입력 특징(feature) |
| 2. 프로젝트 전용 Sigma-like 룰 | 외부 수신자, 첨부, BCC, 반복 전송 등 알려진 정책·시나리오를 명시적 규칙으로 표현 | 가능 | 규칙 근거 및 weak label 후보 |
| 3. 상관 규칙 | 파일 활동→외부 첨부메일처럼 여러 이벤트의 횟수·순서·시간 관계를 판단 | 가능하나 Python/쿼리 엔진 필요 | 시퀀스 특징 및 강한 검토 후보 |
| 4. 공식 SigmaHQ 룰 | Windows 인증·프로세스·권한 변경·로그 삭제 탐지 | 현재 불가 | 운영 SIEM에 해당 로그가 추가된 뒤 보조 근거 |
| 5. 분석가 라벨 | 증거 묶음을 사람이 확인한 결과 | 별도 구축 필요 | 검증용 gold label |

가장 중요한 원칙은 `rule_hit=1`을 공격 정답으로, `rule_hit=0`을 정상 정답으로 간주하지 않는 것이다. Sigma의 `level`은 공격 확률이 아니라 탐지 이벤트의 중요도이며 `falsepositives`도 자동 제외 조건이 아닌 조사 참고사항이다. 따라서 규칙 결과는 `rule_based_evidence` 또는 `weak_label`로 보존해야 한다. [Sigma Rules 공식 문서](https://sigmahq.io/docs/basics/rules.html), [Sigma 룰 규격](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md)

## 2. 샘플 데이터 적합성 확인

### 2.1 실제 테이블과 적용 한계

`샘플데이터.db`를 직접 조회한 결과는 다음과 같다.

| 테이블 | 행 수 | 실제 원천 컬럼 | Sigma/분석에 쓸 수 있는 정보 | 없는 정보와 그 영향 |
|---|---:|---|---|---|
| `email` | 1,314,400 | `id,date,user,pc,to,cc,bcc,from,size,attachments,content` | 발신자 검증, 외부 수신자·도메인, 첨부 수, 메시지 크기, 시간, PC | 발송/수신 `activity`, 파일명·첨부 크기, 메일 상태 없음. 발신 검증 없는 행은 외부 발송으로 단정 불가 |
| `file` | 445,581 | `id,date,user,pc,filename,content` | 파일 이벤트 빈도, 확장자, 이메일 전 선행 파일 활동 | 작업 종류·경로·크기·복사 방향 없음. 실제 반출량 계산 불가 |
| `device` | 405,380 | `id,date,user,pc,activity` | `Connect`/`Disconnect`, 이메일·파일 전후 장치 연결 | 장치 ID·용량·복사량 없음. 연결만으로 USB 유출 확정 불가 |
| `http` | 1,422,900 | `id,date,user,pc,url,content` | 도메인 신규성·빈도, 이메일 전후 웹 활동 | 메서드·상태·전송량·업로드/다운로드 구분 없음 |
| `logon` | 854,859 | `id,date,user,pc,activity` | 로그인 시간, 신규 PC, 선행 로그인 | 성공/실패, IP, 원격 유형 없음. 4625·공인 IP·RDP 룰 실행 불가 |
| 월별 LDAP | 18개 월, 1,000→845명 | 사용자·등록 이메일·직무·조직·상사 | 시점별 발신자 검증, 사내 도메인, 동료집단 기준선 | IAM 권한 변경 이벤트가 아님 |
| `psychometric` | 1,000 | 사용자와 OCEAN 점수 | 연구용 보조 변수 | 악성 라벨이나 위험점수로 직접 사용하면 안 됨 |

현재 파이프라인의 `feature_manifest.json`에 따르면 전체 이메일 중 LDAP 등록 주소와 발신자가 일치하는 `sender_verified` 행은 815,250건이다. 따라서 즉시 적용하는 이메일 발송 룰의 모집단은 원칙적으로 이 815,250건이어야 한다.

### 2.2 권장 공통 필드 매핑

원천 로그를 바로 Sigma에 맞추기보다 정규화 뷰를 먼저 만들고 룰에서는 정규화 필드만 참조한다.

| 표준 필드 | 원천/산식 | 자료형 | 필수 품질 조건 |
|---|---|---|---|
| `event_id` | `email.id` 등 각 테이블의 `id` | string | 테이블명과 함께 유일키로 사용 |
| `event_time` | `date` 파싱 | datetime | 시간대는 별도 확정; 미래 정보를 과거에 사용하지 않음 |
| `user_key` | 활동 로그 `user` | string | 해당 월 LDAP의 `user_id`와 결합 |
| `host` | `pc` | string | 대소문자·공백 정규화 |
| `sender_verified` | `lower(email.from)=lower(해당 월 LDAP.email)` | boolean | 참인 행만 외부 **발송** 규칙에 사용 |
| `recipient_list` | `to`,`cc`,`bcc`를 `;`로 분리·정규화 | array | 빈 CC/BCC는 오류가 아닌 0개로 처리 |
| `external_recipient_count` | 등록 사내 주소/도메인이 아닌 고유 수신자 수 | integer | 내부 도메인 목록을 설정으로 버전 관리 |
| `external_domain_count` | 외부 수신자의 고유 도메인 수 | integer | IDN·대소문자·후행점 정규화 |
| `external_bcc_count` | `bcc` 중 외부 주소 수 | integer | BCC 존재와 외부 BCC를 구분 |
| `attachment_count` | `attachments` | integer | 첨부 크기와 혼동하지 않음 |
| `message_size` | `size` | integer | 단위 미확정임을 메타데이터로 보존 |
| `is_off_hours` | 주말 또는 평일 08:00 이전/19:00 이후 | boolean | 초기 운영값; 근무표·휴일·교대근무 반영 필요 |
| `is_new_external_recipient/domain` | 해당 이벤트 **이전** 이력 집합과 비교 | boolean | 최초 관측(cold start)은 판단 보류 |
| `history_days` | 사용자별 최초 관측 이후 경과일 | integer | 신규성·기준선 신뢰도 판단에 사용 |

Sigma는 사용자 정의 logsource와 변환 파이프라인의 필드 매핑을 지원한다. 다만 필드 매핑은 없는 정보를 생성하지 않으므로, 위 파생값은 ETL/Python에서 먼저 계산해야 한다. [Sigma 사용자 정의 필드·로그소스 매핑](https://sigmahq.io/docs/guide/getting-started.html#custom-field--source-mapping), [pySigma processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines)

## 3. 현재 샘플에 실제 적용할 규칙 카탈로그

아래 규칙 ID는 **SigmaHQ 공식 룰 ID가 아니라 본 프로젝트의 로컬 규칙 ID**다. 단일 이벤트 조건은 Sigma YAML로 표현할 수 있지만, 과거 기준선·고유값 집합·롤링 합계·순서 조건은 전처리 또는 상관 엔진이 필요하다.

### 3.1 이메일 단일 이벤트·행동 규칙

| 우선 | 로컬 룰 ID / 이름 | 정확한 탐지 조건 | 데이터 필드 | 현재 임계값·근거 | 오탐/예외 | 모델 활용 |
|---:|---|---|---|---|---|---|
| 1 | `EML-001 External Recipient` | `sender_verified=true AND external_recipient_count>=1` | `from,to,cc,bcc`, 월별 LDAP | 직접 관찰 조건 | 협력사·고객과 정상 업무 | 위험 신호의 게이트. 단독 양성 라벨 금지 |
| 2 | `EML-002 Attachment to External` | `EML-001 AND attachment_count>=1` | 위 필드 + `attachments` | 1개 이상 | 승인된 자료 전달 | 이진 특징 및 검토 근거 |
| 3 | `EML-003 Large Message vs Prior` | 외부 수신 메일이며 `size > max(사용자 과거 200건 p99, 과거 median+6×MAD)` | `size,user,date` | 현 코드의 과거 전용 강건 기준선 | 정상 대용량 자료, 단위 불명 | `size_robust_z`, 이진 특징. 미래 누출 금지 |
| 4 | `EML-004 Multiple External Targets` | `external_recipient_count>=2 OR external_domain_count>=2` | 파싱한 수신자·도메인 | 샘플 외부메일 p90/p99 기반 운영값 2명; 고위험 3명 | 뉴스레터·배포메일 | 수신자 수 연속값과 hit를 모두 저장 |
| 5 | `EML-005 External BCC` | `external_bcc_count>=1` | `bcc` | 직접 관찰 조건 | 정상 대량메일·개인정보 보호 | 보조 특징; 단독 고위험 금지 |
| 6 | `EML-006 Off-hours External Send` | `EML-001 AND (주말 OR 평일 <08:00 OR >=19:00)` | `date` | 기획/현 코드 초기값 | 교대·재택·해외 협업·휴일 오류 | 개인 시간대 분포와 함께 사용 |
| 7 | `EML-007 New External Recipient` | 충분한 관측 이력 이후, 해당 주소가 사용자의 과거 수신자 집합에 없음 | 시간순 수신자 이력 | cold start 제외; 최소 이력기간을 운영 설정화 | 신규 고객·협력사 | novelty 특징; 승인 도메인 예외 적용 |
| 8 | `EML-008 New External Domain` | 충분한 관측 이력 이후, 외부 도메인이 과거 집합에 없음 | 시간순 도메인 이력 | cold start 제외 | 신규 협력사·도메인 변경 | 수신자 신규성과 별도 특징 |
| 9 | `EML-009 Hourly Burst` | 동일 사용자 외부메일이 롤링 1시간 내 5건 이상 | `user,event_time,EML-001` | 현 코드 운영 초기값 5건; 일별 p99는 4건 | 마감·일괄 보고 | count와 hit를 저장; 고정 시간 버킷보다 롤링 권장 |
| 10 | `EML-010 Weekly Repetition` | 동일 사용자·주에 외부메일 5건 이상 | `user,event_time,EML-001` | 현 코드 초기값 5건 | 정기 보고·영업 업무 | 주간 빈도 특징; 부서/직무 기준선과 비교 |
| 11 | `EML-011 Long-term External Transfer` | 21일 이상 이력이 있고 선행 3개 주 이상에서 외부메일 발생 | 사용자 주별 이력 | NIA 사례의 장기 반복 행태를 조기에 근사 | 지속적인 정상 협업 | 고가치 weak positive 후보이나 사람 검토 필수 |
| 12 | `EML-012 Multi-signal High Risk` | `EML-001`을 제외한 독립 신호 3개 이상 동시 충족 | 위 규칙 hit 집합 | 현 코드 초기값 3개 | 여러 정상 조건의 우연한 결합 | 검토 큐 우선순위; 독립 gold label 아님 |

`EML-004`의 2명, `EML-009`의 5건 등은 보편적인 보안 표준값이 아니라 현재 샘플 분포와 기존 구현에서 얻은 **초기값**이다. 운영 데이터로 바뀌면 직무별 오탐률과 분석가 처리 용량을 기준으로 다시 보정해야 한다.

### 3.2 다중 로그·상관 규칙

| 우선 | 로컬 룰 ID / 이름 | 상관 조건 | 구현 형태 | 현재 가능성 | 해석 제한 | ATT&CK 연결 |
|---:|---|---|---|---:|---|---|
| 1 | `COR-001 File Spike → External Attachment` | 사용자별 당일 파일 이벤트가 이전 30일 기준 `robust z>=3`이고, 이후 2시간 안에 외부 첨부메일 발생. 동일 PC면 근거 강화 | `temporal_ordered` 개념 + Python 조인 | 가능 | 파일 작업 종류·첨부 파일 동일성은 증명 못함 | 데이터 스테이징/유출 징후로 설명하되 확정 매핑 금지 |
| 2 | `COR-002 Device Connect → File Activity → External Mail` | 동일 사용자·PC에서 Connect 후 파일 활동 집중, 이어 외부 첨부메일; 예: 전체 흐름 4시간 이내 | 3단계 순서형 상관 | 부분 가능 | 장치 ID·복사 방향이 없어 USB 유출 확정 불가 | [T1052.001 Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001/)의 분석 아이디어 |
| 3 | `COR-003 Logon → New PC → External Mail` | 충분한 이력 이후 처음 보는 PC 로그인 후 2시간 내 외부메일 | 신규성 전처리 + 순서형 상관 | 가능 | 로그인 성공 여부·원격 여부 없음 | 계정 오용 조사 보조; T1078 확정 탐지로 표기 금지 |
| 4 | `COR-004 New Web Domain → External Mail` | 신규/희귀 웹 도메인 접근 후 1시간 내 신규 외부 도메인 메일 | 도메인 정규화 + 순서형 상관 | 가능 | HTTP 업로드·메일과의 인과관계 없음 | [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/) 조사 보조 |
| 5 | `COR-005 Low-and-slow Transfer` | 30일 동안 외부 활동일 4일 이상 또는 여러 주에 작은 전송이 반복되고 대상이 동일/희귀 | `event_count`/`value_count` + 장기 창 | 가능 | 정상 정기 업무 가능성 큼 | 임계치 회피를 설명하는 [T1030](https://attack.mitre.org/techniques/T1030/)과 개념적으로 관련 |
| 6 | `COR-006 Recipient Fan-out` | 사용자별 일정 시간 내 고유 외부 수신자 수 급증 | `value_count`, group-by user | 가능 | 마케팅·공지 메일 | 전송 규모/확산성 특징 |

Sigma Correlation 규격은 현재 `event_count`, `value_count`, `temporal`, `temporal_ordered`를 정식 유형으로 정의한다. GPT 답변에 언급된 `value_sum`, `value_avg`, `value_percentile`은 초안/확장 논의나 특정 구현체와 혼동될 수 있으므로, **공식 규격 v2.1의 허용 유형으로 단정하여 사용하지 않는다.** 메시지 크기 합계·백분위·강건 Z-score는 Python/SQL 특징 엔진에서 계산하는 편이 안전하다. [Sigma Correlation Rules Specification v2.1](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)

### 3.3 로컬 Sigma YAML 예시

다음은 전처리로 파생 필드를 만든 뒤 사용할 수 있는 이식 가능한 표현 예시다. `product: teiren`과 필드명은 프로젝트 사용자 정의이며, 현재 CSV에 그대로 존재하는 값은 아니다.

```yaml
title: Verified Sender Sends Attachment to External Recipient
id: 8eaac143-817a-4d38-9db0-96242f88e56e
status: experimental
description: Detects a sender-verified email with an attachment to at least one external recipient.
logsource:
    category: email
    product: teiren
    definition: Requires normalized and enriched email events.
detection:
    selection:
        sender_verified: true
        has_external_recipient: true
        attachment_count|gte: 1
    condition: selection
fields:
    - event_time
    - user_key
    - host
    - external_recipient_count
    - attachment_count
falsepositives:
    - Approved partner or customer communication
    - Scheduled business reporting
level: medium
tags:
    - attack.exfiltration
```

실행 시에는 `category: email, product: teiren`을 실제 인덱스/테이블로, 위 표준 필드를 SIEM 필드로 연결하는 pySigma processing pipeline이 필요하다. 비교 연산자의 실제 지원 여부와 변환 결과는 선택한 백엔드에서 반드시 테스트한다.

## 4. 현재 샘플에는 적용할 수 없는 공개 SigmaHQ 룰

아래 룰은 GPT 답변의 취지는 유효하지만 현재 컬럼으로는 탐지할 수 없다. 억지로 근사하지 말고 향후 원천 로그 요구사항으로 분리한다.

| 공개 룰/시나리오 | 필요한 핵심 필드 | 현재 상태 | 향후 활용 |
|---|---|---|---|
| 로그인 실패 반복 및 실패 후 성공 | Windows `EventID 4625/4624`, 결과, IP, 사용자, 시간 | `logon.activity`에는 Logon/Logoff만 있고 실패가 없음 | Windows Security 또는 IdP 인증 로그 수집 후 `event_count`+`temporal_ordered` |
| 공인 IP 실패 로그인 | `4625`, `IpAddress` | IP 없음 | VPN/IdP 허용목록과 결합 |
| 외부 RDP 성공 | `4624`, `LogonType=10`, `IpAddress` | 원격 유형·IP 없음 | 계정 탈취 보조 근거 |
| 로컬 관리자 그룹 추가 | `4732`, 대상 그룹 SID | 권한 변경 로그 없음 | 권한 상승 시퀀스에 사용 |
| 인코딩 PowerShell | 프로세스명, 원본 파일명, 명령행 | 프로세스 로그 없음 | EDR/Sysmon 수집 후 SigmaHQ 룰 사용 |
| 의심 예약작업 생성 | `4698`, `TaskContent`/명령 | 없음 | 지속성 확보 탐지 |
| 보안 이벤트로그 삭제 | `1102` 또는 관련 채널 | 없음 | 공격 시퀀스 후반의 강한 근거 |
| Defender 비활성화 | Defender 이벤트 ID·설정 변경 | 없음 | 방어 회피 근거 |

따라서 MVP 문서에는 이들을 “적용 룰”이 아니라 **2차 데이터 연계 후보**로 표기해야 한다. 현재 `logon.csv`의 `Logon`을 Windows `4624`로, 행 부재를 `4625 미발생`으로 치환하면 잘못된 탐지가 된다.

## 5. 모델 개발에 적용하는 방법

### 5.1 학습 테이블과 특징 설계

권장 기본 단위는 `사용자×일`이며, 사건 재생과 짧은 시퀀스에는 `사용자×30분 창`을 병행한다.

| 특징군 | 구체 변수 예 | 생성 규칙 | 모델에 넣는 이유 |
|---|---|---|---|
| 활동량 | `external_email_count`, `external_recipient_count`, `external_message_size_sum/max` | sender-verified 이벤트만 집계 | 평소 대비 전송 규모 |
| 콘텐츠 메타데이터 | `external_attachment_total`, `bcc_to_external_count` | 원문 주소·본문 대신 수치화 | 개인정보 노출을 줄이며 행위 강도 반영 |
| 신규성 | `new_external_recipient/domain_count`, `new_pc` | 과거만 보는 expanding history | 새 대상·환경 변화 |
| 시간 | `off_hours_external_count`, `weekend_external_count` | 근무표 적용 전에는 초기 규칙 | 시간대 이탈 |
| 반복/속도 | `burst_count`, `external_email_count_7d/30d`, `active_days_30d` | 롤링 창 | 대량과 저속 반복을 함께 포착 |
| 개인 기준선 | 각 지표의 prior-only median, MAD, p99, robust z | 현재 행 이후 데이터를 사용하지 않음 | 사용자별 업무량 차이 보정 |
| 동료집단 | 직무·부서별 percentile | 이벤트 시점의 LDAP 스냅샷 사용 | 신규 직원/cold start 보완 |
| 상관 특징 | `file_spike`, `file_to_email_minutes`, `same_pc`, `sequence_stage` | 시간순 조인 | 단일 이메일보다 강한 맥락 제공 |
| 룰 메타 | hit count, rule IDs, 최고 level | 원인 코드와 함께 저장 | 설명·검토 우선순위. 점수와 중복 주의 |

### 5.2 추천 모델 전략

| 단계 | 권장 방법 | 학습 라벨 | 평가 방법 | 주의사항 |
|---|---|---|---|---|
| MVP 기준선 | 강건 Z-score + 명시적 룰 점수 | 불필요 | 상위 K건 수동 검토, 기간별 안정성 | 가장 설명 가능하며 현재 코드와 일치 |
| 비교 모델 | Isolation Forest 또는 유사 비지도 모델 | 불필요 | 룰과 독립적으로 뽑힌 상위 이상 사용자 검토 | 범주·스케일 처리, 오염률 임의 고정 주의 |
| 약한 지도 | 규칙별 labeling function: `1/0/-1`이 아니라 보통 `1/ABSTAIN`, 확실한 정상 규칙만 `0` | 확률형 weak label | 사람이 라벨한 별도 검증셋 | 상관된 룰을 독립 투표처럼 세지 않음 |
| 최종 지도학습 | 분석가 gold label 또는 CERT answer key | 독립 정답 | 시간순 train/validation/test, PR-AUC, Recall@K, alert precision | 규칙 점수로 만든 라벨을 같은 규칙 특징으로 평가하는 순환논리 금지 |

규칙·휴리스틱을 라벨링 함수로 취급하고 충돌·상관을 고려해 확률형 라벨을 생성하는 접근은 Snorkel의 weak supervision 구조와 맞는다. 다만 소량의 독립 수동 검증셋은 여전히 필요하다. [Snorkel 논문](https://arxiv.org/abs/1711.10160)

### 5.3 권장 라벨 스키마

| 필드 | 값 예 | 의미 |
|---|---|---|
| `weak_label` | `1`, `-1` | 규칙이 충분한 양성 근거를 냈으면 1, 아니면 미확정(-1). 미탐지를 정상 0으로 두지 않음 |
| `rule_ids` | `EML-002|EML-008|COR-001` | 어떤 규칙이 근거인지 |
| `label_source` | `rule`, `injected_scenario`, `analyst` | 라벨의 생성 주체 |
| `analyst_label` | `confirmed_suspicious`, `benign`, `uncertain` | 사람 검토 결과 |
| `label_version` | `email-risk-v1.1` | 임계값·정규화 변경 추적 |
| `evidence_event_ids` | 원천 이벤트 ID 목록 | 재현 가능한 조사 근거 |

`NORMAL_OR_UNCLASSIFIED`는 이름 그대로 “현재 규칙 신호가 없음”이지 확인된 정상은 아니다. 모델 학습용 `0`은 승인된 정상 시나리오나 분석가 확인 사례에서만 가져오는 것이 안전하다.

### 5.4 점수 결합 권고

현재 코드의 점수는 탐색·우선순위화에는 쓸 수 있지만 확률로 표현하면 안 된다. 권장 출력은 다음처럼 분리한다.

| 출력 | 산식/내용 | 표시 방식 |
|---|---|---|
| `behavior_anomaly_score` | 개인 과거 대비 강건 Z-score를 0~100으로 정규화 | 행동 이탈 정도 |
| `rule_evidence` | 룰 ID, 조건, 원천 이벤트, 예외 후보 | 알려진 패턴과의 일치 근거 |
| `sequence_score` | 파일→메일 등 순서 완성도·시간 간격·동일 PC | 시나리오 맥락 |
| `model_anomaly_score` | Isolation Forest 등 독립 모델 출력 | 비교/보조 점수 |
| `review_priority` | 위 요소와 업무 허용목록을 결합한 P1~P4 | 분석가 처리 순서 |

초기 운영 규칙 예시는 `강한 상관 시퀀스 완성 → P1 후보`, `서로 다른 신호 3개 이상 → P2 후보`, `단일 외부메일 → P3/P4 관찰`이다. 이는 Sigma나 MITRE가 제공하는 공식 확률식이 아니라 프로젝트의 운영 정책임을 문서화해야 한다.

## 6. 구현 순서와 검증 기준

| 순서 | 작업 | 완료 기준 |
|---:|---|---|
| 1 | 정규화 뷰 생성 | 주소 분리, 해당 월 LDAP 결합, `sender_verified`, 내부/외부 판정 재현 가능 |
| 2 | EML-001~012 계산 | 각 hit에 `rule_id`, `reason_code`, `event_id`, 버전 저장 |
| 3 | COR-001 우선 구현 | 파일 스파이크→2시간 내 외부 첨부메일과 동일 PC 여부 재생 가능 |
| 4 | 사용자×일/30분 특징 생성 | 모든 롤링·기준선이 과거 데이터만 사용 |
| 5 | 규칙 기준선과 Isolation Forest 비교 | 동일 시간 분할, 상위 K 중 중복·고유 탐지 분석 |
| 6 | 분석가 검토 표본 구축 | 고위험·중간·무신호 층화 표본과 판정 사유 보존 |
| 7 | 임계값 튜닝 | Precision@K, 일평균 알림량, 부서별 오탐 편향으로 조정 |
| 8 | 운영 SIEM 매핑 | pySigma 변환 결과와 원본 쿼리의 이벤트 수·샘플이 일치 |

검증 지표는 클래스 불균형을 고려해 정확도보다 `Precision@K`, `Recall@K`, PR-AUC, 일평균 알림 수, 분석가 확인 정탐률을 우선한다. 사용자별 랜덤 분할보다 **시간순 분할**을 사용해 미래 정보 유출을 막는다.

## 7. 데이터 추가 요청 우선순위

| 우선 | 요청 데이터 | 필요한 필드 | 가능해지는 탐지 |
|---:|---|---|---|
| 1 | 메일 게이트웨이/Exchange 감사 로그 | 발송·수신 방향, Message-ID, 첨부명·크기, action, delivery status, 정책 ID | 실제 외부 발송 확인, 첨부 기반 DLP 룰 |
| 2 | IdP/Windows 인증 로그 | 성공/실패, IP, 인증 방식, 원격 유형, 세션 ID | 실패 폭증, 실패→성공, 공인 IP/RDP Sigma 룰 |
| 3 | EDR/Sysmon | 프로세스, 명령행, 부모 프로세스, 해시 | PowerShell·압축·스테이징·도구 실행 룰 |
| 4 | DLP/파일 감사 | 경로, 작업, 파일 크기·해시, source/destination, 민감도 | 어떤 파일이 첨부/복사됐는지 상관 |
| 5 | USB 상세 로그 | 장치 ID, 매체 유형, 마운트·쓰기·바이트 | T1052.001에 가까운 실증 탐지 |
| 6 | 근무표·휴일·승인목록 | 교대, 출장, 승인 협력사·도메인, 서비스 계정 | 야간·신규 도메인 오탐 감소 |
| 7 | CERT answer key 또는 공격 주입 기록 | 악성 사용자, 시나리오, 시간 구간 | 독립 성능 평가와 지도학습 |

CMU SEI는 이 데이터셋을 배경 및 악성 사용자 활동을 포함한 합성 데이터로 설명하며, 악성 시나리오와 사용자 ID는 별도의 answer key에 있다고 명시한다. 현재 제공 DB에 정답 테이블이 없으므로, 원본 릴리스와 정확히 대응하는 answer key를 확보하기 전에는 탐지 정확도를 주장할 수 없다. [CMU SEI Insider Threat Test Dataset](https://www.sei.cmu.edu/library/insider-threat-test-dataset/)

## 8. 출처와 적용 범위

| 출처 | 이 문서에서 사용한 내용 | 적용 시 주의 |
|---|---|---|
| [Sigma Rules](https://sigmahq.io/docs/basics/rules.html) | 룰 구조, logsource, level·false positives의 성격 | 룰 hit는 공격 확정이 아님 |
| [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md) | 정식 YAML 필드와 메타데이터 | 백엔드별 변환 검증 필요 |
| [Sigma Correlation Rules v2.1](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html) | `event_count`, `value_count`, `temporal`, `temporal_ordered` | 모든 SIEM이 동일하게 지원한다는 뜻은 아님 |
| [Sigma Getting Started](https://sigmahq.io/docs/guide/getting-started.html) | 사용자 정의 logsource·필드 매핑 | 파생 특징 계산을 대신하지 않음 |
| [pySigma pipelines](https://sigmahq.io/docs/digging-deeper/pipelines) | SIEM 인덱스·필드 변환 | 테이렌 백엔드 지원/쿼리 문법 별도 확인 |
| [CMU SEI Insider Threat Test Dataset](https://www.sei.cmu.edu/library/insider-threat-test-dataset/) | 합성 데이터 성격과 별도 answer key | 정확한 릴리스 일치 확인 필요 |
| [MITRE ATT&CK T1052](https://attack.mitre.org/techniques/T1052/) | 이동식 매체 유출 탐지 맥락 | 현재 장치 로그만으로 유출 확정 불가 |
| [MITRE ATT&CK T1567](https://attack.mitre.org/techniques/T1567/) | 웹 서비스 기반 유출 맥락 | 현재 HTTP 로그에는 업로드 정보가 없음 |
| [MITRE ATT&CK T1030](https://attack.mitre.org/techniques/T1030/) | 임계치 이하 분할·저속 전송 관점 | 메일 반복은 개념적 대응이며 기법 확정이 아님 |
| [Snorkel](https://arxiv.org/abs/1711.10160) | 여러 휴리스틱을 weak supervision으로 결합 | 독립 수동 검증셋 필요 |

## 9. 기획안에 넣을 수 있는 최종 문구

> 본 프로젝트는 사용자별 과거 이메일 행동 기준선과 프로젝트 전용 Sigma-like 탐지 규칙, 다중 로그 시간 상관분석을 결합한다. Sigma 규칙 결과는 공격의 정답이 아니라 알려진 위험 패턴과 일치했다는 규칙 기반 근거로 저장하며, 규칙 미탐지 데이터는 정상으로 간주하지 않는다. 현재 샘플에서는 LDAP 등록 주소와 발신 주소가 일치하는 이벤트를 외부 발송 후보의 모집단으로 제한하고, 외부 수신자·첨부·메시지 크기·BCC·시간대·신규 대상·반복성 및 파일→이메일 시퀀스를 분석한다. 최종 성능 평가는 별도 answer key 또는 분석가 검토 라벨로 수행하고, Windows 인증·프로세스·권한 변경 SigmaHQ 룰은 관련 운영 로그가 연계된 2차 단계에서 적용한다.

---

### 용어 주의

- 여기서 **Sigma**는 표준화된 SIEM 탐지 규칙 형식을 뜻하며, 통계의 표준편차 기호 σ나 Sigma Computing 제품을 뜻하지 않는다.
- `Sigma-like`는 탐지 조건·메타데이터·근거 보존 방식을 Sigma 구조로 관리한다는 의미다. 현 샘플용 로컬 룰이 SigmaHQ 공식 저장소의 검증된 룰이라는 뜻은 아니다.
- ATT&CK 매핑은 조사 맥락과 탐지 목적을 설명하기 위한 것이며, 규칙 hit만으로 해당 공격 기법이 실제 수행됐음을 확정하지 않는다.
