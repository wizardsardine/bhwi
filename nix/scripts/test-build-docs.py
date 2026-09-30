#!/usr/bin/env python3
"""Exercise discovery and links through the pinned mdBook HTML renderer."""

from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import unquote, urljoin, urlsplit


class BookPage(HTMLParser):
    def __init__(self, path):
        super().__init__()
        self.navigation = []
        self.links = []
        self.images = []
        self.body = []
        self.chapter_depth = 0
        self.in_main = False
        self.link = None
        self.feed(path.read_text(encoding="utf-8"))

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "ol" and (
            self.chapter_depth or "chapter" in attributes.get("class", "").split()
        ):
            self.chapter_depth += 1
        if tag == "main":
            self.in_main = True
        if tag == "a":
            self.link = (unquote(attributes.get("href", "")), [], self.chapter_depth)
        if tag == "img" and self.in_main:
            self.images.append(unquote(attributes["src"]))

    def handle_data(self, data):
        if self.link is not None:
            self.link[1].append(data)
        if self.in_main:
            self.body.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.link is not None:
            href, text, chapter = self.link
            link = (href, "".join(text).strip())
            self.links.append(link)
            if chapter:
                self.navigation.append(link)
            self.link = None
        if tag == "ol" and self.chapter_depth:
            self.chapter_depth -= 1
        if tag == "main":
            self.in_main = False


class BuildDocsTest(unittest.TestCase):
    def test_rendered_discovery_and_removal(self):
        repository = Path(__file__).resolve().parents[2]
        generator = repository / "nix/scripts/build-docs.py"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "docs/nested").mkdir(parents=True)
            (source / "nix").mkdir()
            shutil.copyfile(repository / "nix/book.toml", source / "nix/book.toml")
            (source / "README.md").write_text(
                "# Test introduction\n\nINTRODUCTION_BODY\n", encoding="utf-8"
            )
            shared_title = "Shared [label] *title*"
            pages = {
                "docs/z.md": f"# {shared_title} ###\n\nLOWERCASE_BODY\n",
                "docs/nested/Übersicht.md": "# Unicode guide\n\nUNICODE_BODY\n",
                "docs/Z.md": f"# {shared_title}\n\nUPPERCASE_BODY\n",
                "docs/fallback.md": "\nFallback body without a heading.\n",
                "docs/.hidden.md": "# Hidden page\n",
                "docs/.private/page.md": "# Hidden directory page\n",
                "docs/sUmMaRy.Md": "# Ignored summary\n",
                "docs/asset.MD": "# Uppercase suffix is not a chapter\n",
                "website/README.md": "# Unrelated website page\n",
                "outside/page.md": "# Symlink-only page\n",
            }
            for path, content in pages.items():
                destination = source / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")
            guide = source / "docs/nested/Guide (USB).md"
            guide.write_text(
                "\n# USB guide ###\n\nNESTED_GUIDE_BODY\n\n"
                "[Root README](../../README.md)\n\n![Device image](device.svg)\n",
                encoding="utf-8",
            )
            image = source / "docs/nested/device.svg"
            image.write_text(
                '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
                '<rect width="10" height="10" fill="blue"/></svg>\n',
                encoding="utf-8",
            )
            (source / "docs/linked.md").symlink_to(source / "docs/Z.md")
            (source / "docs/linked-directory").symlink_to(
                source / "outside", target_is_directory=True
            )

            def generate(destination):
                return subprocess.run(
                    [sys.executable, str(generator), str(source), str(destination)],
                    capture_output=True,
                    text=True,
                )

            def render(name):
                book = root / name
                generated = generate(book)
                self.assertEqual(generated.returncode, 0, generated.stderr)
                output = root / f"{name}-html"
                subprocess.run(
                    ["mdbook", "build", str(book), "--dest-dir", str(output)],
                    check=True,
                )
                return book, output

            book, output = render("first")
            expected_navigation = [
                ("README.html", "Test introduction"),
                ("docs/Z.html", shared_title),
                ("docs/fallback.html", "fallback"),
                ("docs/nested/Guide (USB).html", "USB guide"),
                ("docs/nested/Übersicht.html", "Unicode guide"),
                ("docs/z.html", shared_title),
                ("API.html", "API reference"),
            ]
            introduction = BookPage(output / "README.html")
            # mdBook 0.5 renders the shared sidebar separately from chapter pages.
            self.assertEqual(BookPage(output / "toc.html").navigation, expected_navigation)
            self.assertIn("INTRODUCTION_BODY", "".join(introduction.body))
            self.assertIn("INTRODUCTION_BODY", "".join(BookPage(output / "index.html").body))
            nested = output / "docs/nested/Guide (USB).html"
            rendered_guide = BookPage(nested)
            self.assertIn("NESTED_GUIDE_BODY", "".join(rendered_guide.body))
            readme_link = next(href for href, title in rendered_guide.links if title == "Root README")
            self.assertEqual(readme_link, "../../README.html")
            self.assertEqual(Path(urlsplit(urljoin(nested.as_uri(), readme_link)).path), output / "README.html")
            self.assertIn("device.svg", rendered_guide.images)
            for image_src in set(rendered_guide.images):
                rendered_image = nested.parent / image_src
                self.assertEqual(rendered_image.read_bytes(), image.read_bytes())
            for excluded in (
                "docs/.hidden.html", "docs/.private", "docs/linked.html",
                "docs/linked-directory", "docs/sUmMaRy.Md", "website", "outside",
            ):
                self.assertFalse((output / excluded).exists(), excluded)
            self.assertIn("Fallback body without a heading.", "".join(BookPage(output / "docs/fallback.html").body))
            self.assertNotEqual(generate(book).returncode, 0)

            guide.unlink()
            _, updated = render("removed")
            self.assertEqual(
                BookPage(updated / "toc.html").navigation,
                [entry for entry in expected_navigation if entry[0] != "docs/nested/Guide (USB).html"],
            )
            self.assertFalse((updated / "docs/nested/Guide (USB).html").exists())

            for index, character in enumerate("\r\n<>#?%\\&"):
                invalid = source / "docs" / f"Bad{character}path.md"
                invalid.write_text("# Invalid path\n", encoding="utf-8")
                failed = generate(root / f"invalid-{index}")
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(repr(invalid.relative_to(source).as_posix()), failed.stderr)
                invalid.unlink()

            shutil.rmtree(source / "docs")
            (source / "docs").mkdir()
            _, empty = render("empty")
            self.assertEqual(
                BookPage(empty / "toc.html").navigation,
                [expected_navigation[0], expected_navigation[-1]],
            )


if __name__ == "__main__":
    unittest.main()
