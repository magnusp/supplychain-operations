import re
from urllib.parse import quote, unquote

from depgraph_gap.domain import PackageId, Purl, Repository

_LOWERCASE_TYPES = frozenset(
    {"bitbucket", "composer", "github", "githubactions", "golang", "npm", "pypi"}
)
_PYPI_SEPARATORS = re.compile(r"[-_.]+")
_GO_MAJOR_VERSION_SUFFIX = r"(?:/v(?:[2-9]|[1-9][0-9]+))?"


def parse_purl(text: str) -> Purl | None:
    if not text.startswith("pkg:"):
        return None
    remainder = text.removeprefix("pkg:").lstrip("/")
    remainder = remainder.partition("#")[0].partition("?")[0]
    path, version = _split_version(remainder)
    segments = [unquote(segment) for segment in path.split("/") if segment]
    if len(segments) < 2:
        return None
    purl_type = segments[0].lower()
    name = segments[-1]
    namespace_segments = segments[1:-1]
    if purl_type in _LOWERCASE_TYPES:
        name = name.lower()
        namespace_segments = [segment.lower() for segment in namespace_segments]
    if purl_type == "pypi":
        name = _PYPI_SEPARATORS.sub("-", name)
    namespace = "/".join(_encode(segment) for segment in namespace_segments) or None
    package = PackageId(type=purl_type, namespace=namespace, name=_encode(name))
    return Purl(package=package, version=_encode(version) if version else None)


def identifies_repository_module(purl: Purl, repository: Repository) -> bool:
    if purl.type != "golang":
        return False
    module_path = "/".join(part for part in (purl.package.namespace, purl.package.name) if part)
    expected = f"github.com/{re.escape(repository.owner.lower())}/{re.escape(repository.name.lower())}"
    return re.fullmatch(expected + _GO_MAJOR_VERSION_SUFFIX, module_path) is not None


def _split_version(path_and_version: str) -> tuple[str, str | None]:
    at = path_and_version.rfind("@")
    if at > path_and_version.rfind("/"):
        return path_and_version[:at], unquote(path_and_version[at + 1 :])
    return path_and_version, None


def _encode(segment: str) -> str:
    return quote(segment, safe="+:")
