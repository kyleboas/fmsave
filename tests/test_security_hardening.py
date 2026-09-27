"""Regressions for the fork's input and spreadsheet-export hardening."""

from __future__ import annotations

import csv
import io
import random
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import pytest

import fmsave
import fmsave._container as container
from fmsave import cli, export
from fmsave._errors import CorruptSaveError, SaveChangedError
from tests.fixtures.container import SectionFrame, build_container_fragment, zstd


def region_index(tmp_path: Path, **limits: int) -> container.ContainerIndex:
    random_source = random.Random(0)
    frames = tuple(zstd.compress(random_source.randbytes(4096)) for _ in range(8))
    path = build_container_fragment(
        [SectionFrame("example", b"x", unlisted_frames_after=frames)], attachments=()
    ).write(tmp_path / "region.fm")
    return container.read_index(path, container.ContainerLimits(**limits))


def test_region_payloads_are_read_only_as_consumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = region_index(tmp_path)
    name = "unlisted_after_example"
    spans = container.walk_frames(index, name)
    payload_reads: list[tuple[int, int]] = []
    handles: list[BinaryIO] = []
    original_read = container.read_exact

    def recording_read(stream: BinaryIO, offset: int, length: int, filename: str) -> bytes:
        if length > 128:
            payload_reads.append((offset, length))
            handles.append(stream)
        return original_read(stream, offset, length, filename)

    monkeypatch.setattr(container, "read_exact", recording_read)
    frames = container.read_region_frames(index, name)
    assert payload_reads == []
    assert len(next(frames)) == 4096
    assert payload_reads == [(spans[0].offset, spans[0].size)]
    assert all(handle.closed for handle in handles)
    assert len(list(frames)) == 7
    assert payload_reads == [(span.offset, span.size) for span in spans]


def test_unlisted_compressed_cap_rejects_before_payload_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = region_index(tmp_path, frame_compressed_cap=1024)
    original_read = container.read_exact

    def bounded_read(stream: BinaryIO, offset: int, length: int, filename: str) -> bytes:
        assert length <= 1024
        return original_read(stream, offset, length, filename)

    monkeypatch.setattr(container, "read_exact", bounded_read)
    with pytest.raises(CorruptSaveError, match="compressed-frame cap"):
        list(container.read_region_frames(index, "unlisted_after_example"))


def test_listed_compressed_cap_is_checked_in_directory(tmp_path: Path) -> None:
    body = random.Random(0).randbytes(4096)
    path = build_container_fragment([SectionFrame("example", body)]).write(tmp_path / "listed.fm")
    with pytest.raises(CorruptSaveError, match="compressed-frame cap"):
        container.read_index(path, container.ContainerLimits(frame_compressed_cap=1024))


def test_region_decompression_uses_remaining_total_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index = region_index(tmp_path, total_decompressed_cap=4107)
    original_decompress = container.decompress_frame
    caps: list[int] = []

    def recording_decompress(
        compressed: bytes, *, expected_size: int | None, cap: int, what: str, file_name: str
    ) -> bytes:
        caps.append(cap)
        return original_decompress(
            compressed, expected_size=expected_size, cap=cap, what=what, file_name=file_name
        )

    monkeypatch.setattr(container, "decompress_frame", recording_decompress)
    frames = container.read_region_frames(index, "unlisted_after_example")
    assert len(next(frames)) == 4096
    with pytest.raises(CorruptSaveError):
        next(frames)
    assert caps == [4106, 10]  # One byte belongs to the listed section.


def test_lazy_region_reads_recheck_the_file_between_frames(tmp_path: Path) -> None:
    index = region_index(tmp_path)
    frames = container.read_region_frames(index, "unlisted_after_example")
    next(frames)
    index.path.write_bytes(b"changed")
    with pytest.raises(SaveChangedError):
        next(frames)


def test_relative_save_path_survives_chdir(
    career_save_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(career_save_path.parent)
    with fmsave.open(career_save_path.name) as save:
        monkeypatch.chdir(tmp_path)
        assert len(save.clubs()) > 0


@dataclass(frozen=True)
class SpreadsheetRecord:
    name: str
    amount: int
    aliases: tuple[str, ...]


@pytest.mark.parametrize(
    "text",
    [
        "=1+1",
        "+SUM(1,2)",
        "-1+1",
        "@SUM(1,2)",
        " =1+1",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        "\x00=1+1",
        "\u00a0=1+1",
        "\u2003\x00=1+1",
        "\x00\u3000=1+1",
        "＝1+1",
        "＋1+1",
        "－1+1",
        "＠SUM(1,2)",
        "\tplain",
        "\rplain",
        "\nplain",
    ],
)
@pytest.mark.parametrize("writer", ["flat", "table", "cli", "cli-selected"])
def test_csv_formula_like_text_is_escaped_at_every_export_boundary(
    text: str, writer: str, tmp_path: Path
) -> None:
    record = SpreadsheetRecord(text, -5, (text, "safe"))
    stream = io.StringIO(newline="")
    if writer == "flat":
        export.write_csv(
            [{"name": text, "amount": -5, "aliases": record.aliases}],
            ["name", "amount", "aliases"],
            stream,
        )
    elif writer == "table":
        path = tmp_path / "table.csv"
        fmsave.Table([record], SpreadsheetRecord).write_csv(path)
        stream.write(path.read_bytes().decode("utf-8"))
    else:
        columns = ["name", "amount", "aliases"] if writer == "cli-selected" else None
        cli._write_records([record], SpreadsheetRecord, "csv", columns, stream)
    rows = list(csv.DictReader(io.StringIO(stream.getvalue(), newline="")))
    assert rows == [{"name": "'" + text, "amount": "-5", "aliases": "'" + text + ";safe"}]


def test_csv_headers_are_escaped_and_json_preserves_text() -> None:
    stream = io.StringIO()
    export.write_csv([{"=header": "ordinary"}], ["=header"], stream)
    assert stream.getvalue() == "'=header\r\nordinary\r\n"
    stream = io.StringIO()
    export.write_json([{"name": "=1+1"}], stream)
    assert '"name": "=1+1"' in stream.getvalue()
