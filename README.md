# Landmine

> 코드를 건드리기 전에, 묻혀 있는 지뢰를 찾는다.

Landmine은 Claude Code와 Codex를 위한 code-risk discovery plugin이다. 코드의 현재 모습만 검사하지 않고 Git 이력, 테스트, 의존 관계를 함께 분석하여 “왜 존재하는가”, “무엇을 당연하게 믿는가”, “바꾸면 어디까지 깨질 수 있는가”, “어떻게 안전하게 바꿀 것인가”에 답한다.

현재 Phase 0/1 vertical slice가 구현되어 `landmine why path[:line[-end]]`를 로컬 Git
증거와 함께 Markdown 또는 `landmine.result.v1` JSON으로 출력한다. 나머지 세 capability는
CLI에 표시되지만 후속 Phase 전까지 실행되지 않는다.

## Four capabilities

| Command | Question | Primary evidence |
|---|---|---|
| `landmine why` | 이 코드가 왜 생겼고 지금도 필요한가? | blame, log, diff, tests |
| `landmine assumptions` | 이 코드가 암묵적으로 믿는 것은 무엇인가? | branches, validation gaps, contracts |
| `landmine blast` | 이 변경이 어디까지 영향을 미치는가? | references, dependency graph, co-change |
| `landmine defuse` | 어떻게 가장 안전하게 변경할 것인가? | prior findings, characterization tests |

## Example

```bash
landmine why src/routing.py:214
landmine assumptions src/routing.py --format json
landmine blast "remove HospitalFallback" --base main
landmine defuse src/routing.py:214 --goal "support empty results"
```

에이전트 환경에서는 자연어로도 호출한다.

```text
/landmine why src/routing.py:214
/landmine blast HospitalFallback을 제거하면 어디까지 깨질지 조사해줘
```

## MVP promise

- 로컬 Git 저장소에서 read-only 분석
- 명시적 근거와 불확실성 표시
- 사람용 Markdown 및 `landmine.result.v1` JSON 출력
- 단일 파일/심볼/줄 범위 중심 분석
- Python 3.11+ 표준 라이브러리 우선 구현

MVP는 코드를 자동 수정하거나, 원격 issue/PR을 조회하거나, 완전한 정적 분석을 보장하지 않는다.

## Documentation map

- [PRODUCT_SPEC.md](PRODUCT_SPEC.md): 사용자, 범위, acceptance criteria
- [ARCHITECTURE.md](ARCHITECTURE.md): 컴포넌트, Git 분석, 점수, hook 전략
- [COMMANDS.md](COMMANDS.md): CLI와 agent command 계약
- [OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md): JSON/YAML 구조
- [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md): 작업 순서와 단계별 완료 조건
- [EVALUATION.md](EVALUATION.md): fixtures, 평가셋, 품질 게이트
- [CODEX_HANDOFF.md](CODEX_HANDOFF.md): Codex가 질문 없이 구현을 시작하는 지시
- [AGENTS.md](AGENTS.md): 저장소 작업 규칙
- [CONTRIBUTING.md](CONTRIBUTING.md): 개발·PR 규칙
- [SECURITY.md](SECURITY.md): 위협 모델과 안전 원칙

## Repository

```text
landmine/
├── .codex-plugin/plugin.json
├── skills/landmine/
│   ├── SKILL.md
│   └── agents/openai.yaml
├── src/landmine/
│   ├── cli.py
│   ├── domain.py
│   ├── git.py
│   ├── scoring.py
│   ├── renderers.py
│   └── analyzers/why.py
├── tests/{unit,integration,fixtures}/
├── hooks/
├── scripts/
└── docs in this root
```

## Development

```bash
uv run --extra dev pytest
uv run --extra dev ruff format --check .
uv run --extra dev ruff check .
uv run --extra dev mypy src
```

후속 구현은 [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)의 Phase 순서를 따른다.
