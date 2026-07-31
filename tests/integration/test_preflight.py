from landmine.git import preflight
from tests.conftest import GitFixture


def test_preflight_detects_dirty_worktree(git_fixture: GitFixture) -> None:
    git_fixture.commit("initial", "Initial", {"tracked.txt": "clean\n"})
    (git_fixture.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    state, _ = preflight(git_fixture.root)
    assert state.dirty is True


def test_preflight_detects_shallow_repository(git_fixture: GitFixture) -> None:
    head = git_fixture.commit("initial", "Initial", {"tracked.txt": "clean\n"})
    shallow_file = git_fixture.root / ".git" / "shallow"
    shallow_file.write_text(f"{head}\n", encoding="ascii")
    state, _ = preflight(git_fixture.root)
    assert state.shallow is True


def test_preflight_uses_repository_root_from_child(git_fixture: GitFixture) -> None:
    git_fixture.commit("initial", "Initial", {"src/tracked.txt": "clean\n"})
    state, runner = preflight(git_fixture.root / "src")
    assert state.root == "."
    assert runner.cwd == git_fixture.root.resolve()
