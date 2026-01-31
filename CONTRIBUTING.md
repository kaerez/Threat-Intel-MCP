# Contributing to Threat Intelligence MCP

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, constructive, and professional in all interactions.

## Getting Started

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Git

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Ansvar-Systems/Threat-Intel-MCP.git
   cd Threat-Intel-MCP
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Start services**
   ```bash
   docker-compose up -d postgres redis
   ```

5. **Run tests**
   ```bash
   pytest tests/ -v
   ```

## How to Contribute

### Reporting Bugs

1. **Search existing issues** to avoid duplicates
2. **Use the bug report template** when creating issues
3. Include:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Features

1. **Search existing issues** for similar suggestions
2. **Use the feature request template**
3. Explain:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative approaches considered

### Submitting Changes

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our coding standards
4. **Write tests** for new functionality
5. **Run the test suite**
   ```bash
   pytest tests/ -v
   ruff check src/ tests/
   mypy src/
   ```
6. **Commit with clear messages**
   ```bash
   git commit -m "feat: add new feature description"
   ```
7. **Push and create a Pull Request**

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/)
- Use [ruff](https://github.com/astral-sh/ruff) for linting
- Use [mypy](https://mypy.readthedocs.io/) for type checking
- Maximum line length: 100 characters

### Code Quality

```bash
# Lint code
ruff check src/ tests/

# Format code
ruff format src/ tests/

# Type check
mypy src/
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Examples:
```
feat: add semantic search for CAPEC patterns
fix: handle missing CVE description gracefully
docs: update API documentation for new endpoints
test: add integration tests for D3FEND sync
```

### Testing

- Write tests for all new functionality
- Maintain or improve code coverage
- Use pytest fixtures for common setup
- Mock external API calls in unit tests

```python
# Example test structure
class TestFeatureName:
    """Tests for feature_name module."""

    def test_basic_functionality(self):
        """Test basic case."""
        result = function_under_test(input)
        assert result == expected

    def test_edge_case(self):
        """Test edge case handling."""
        ...
```

### Documentation

- Add docstrings to all public functions and classes
- Update README.md for user-facing changes
- Update docs/ for architectural changes
- Include examples in docstrings

```python
def function_name(param: str) -> dict:
    """Short description of function.

    Args:
        param: Description of parameter

    Returns:
        Description of return value

    Raises:
        ValueError: When param is invalid

    Example:
        >>> function_name("example")
        {"result": "value"}
    """
```

## Project Structure

```
threat-intel-mcp/
├── src/cve_mcp/           # Main source code
│   ├── api/               # MCP tool definitions
│   ├── ingest/            # Data parsers
│   ├── models/            # SQLAlchemy models
│   ├── services/          # Business logic
│   └── tasks/             # Sync tasks
├── tests/                 # Test suite
│   ├── ingest/            # Parser tests
│   ├── integration/       # Integration tests
│   └── ...
├── docs/                  # Documentation
└── .github/workflows/     # CI/CD
```

## Pull Request Process

1. **Ensure CI passes** - All tests and checks must pass
2. **Update documentation** - If needed
3. **Add to CHANGELOG** - For significant changes
4. **Request review** - From maintainers
5. **Address feedback** - Respond to review comments
6. **Squash commits** - If requested

### PR Checklist

- [ ] Tests pass locally
- [ ] Linting passes (`ruff check`)
- [ ] Type checking passes (`mypy`)
- [ ] Documentation updated (if needed)
- [ ] Commit messages follow conventions
- [ ] No secrets or credentials in code

## Getting Help

- **Documentation**: Check docs/ directory
- **Issues**: Search existing issues
- **Discussions**: Use GitHub Discussions for questions

## Recognition

Contributors will be recognized in:
- Release notes
- Contributors list (if we add one)
- Git history

Thank you for contributing!
