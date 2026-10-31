//! Formatted notes: **bold**, *italic*, `code`, code blocks and tables,
//! written with Markdown's marks.
//!
//! Notes stay plain text in the vault, so sync, backups, the browser
//! extension and the Android app keep reading them (as readable text with
//! the marks). The details page shows them formatted; the entry form has a
//! small toolbar that puts the marks in.

use crate::tr;
use gtk::prelude::*;

/// A piece of a note, as shown.
#[derive(Debug, PartialEq, Eq)]
enum Block {
    /// Lines of text (inline marks applied when shown).
    Text(String),
    /// A fenced ``` block, shown as is in a fixed-width font.
    Code(String),
    /// A table: its header and body rows of cells.
    Table {
        header: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

/// The cells of a table line (`| a | b |`), or `None` if it is not one.
fn table_cells(line: &str) -> Option<Vec<String>> {
    let line = line.trim();
    if !line.starts_with('|') || line.len() < 2 {
        return None;
    }
    let inner = line.trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    Some(
        inner
            .split('|')
            .map(|cell| cell.trim().to_string())
            .collect(),
    )
}

/// `| --- | :---: |`: the line under a table's header.
fn is_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|cell| {
            let dashes = cell.trim_matches(':');
            !dashes.is_empty() && dashes.chars().all(|c| c == '-')
        })
}

fn parse(notes: &str) -> Vec<Block> {
    let lines: Vec<&str> = notes.lines().collect();
    let mut blocks = Vec::new();
    let mut text: Vec<&str> = Vec::new();
    let flush = |text: &mut Vec<&str>, blocks: &mut Vec<Block>| {
        // Blank lines around a table or a code block are spacing, not text.
        let joined = text.join("\n");
        if !joined.trim().is_empty() {
            blocks.push(Block::Text(joined.trim_matches('\n').to_string()));
        }
        text.clear();
    };
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim_start().starts_with("```") {
            // Up to the closing fence (or the end of the note).
            let end = lines[i + 1..]
                .iter()
                .position(|l| l.trim_start().starts_with("```"))
                .map(|offset| i + 1 + offset);
            flush(&mut text, &mut blocks);
            let body = &lines[i + 1..end.unwrap_or(lines.len())];
            blocks.push(Block::Code(body.join("\n")));
            i = end.map_or(lines.len(), |end| end + 1);
            continue;
        }
        let header = table_cells(line);
        let separator = lines.get(i + 1).and_then(|next| table_cells(next));
        if let (Some(header), Some(separator)) = (header, separator) {
            if is_separator(&separator) {
                flush(&mut text, &mut blocks);
                let mut rows = Vec::new();
                i += 2;
                while let Some(cells) = lines.get(i).and_then(|l| table_cells(l)) {
                    rows.push(cells);
                    i += 1;
                }
                blocks.push(Block::Table { header, rows });
                continue;
            }
        }
        text.push(line);
        i += 1;
    }
    flush(&mut text, &mut blocks);
    blocks
}

/// Code in a line: a fixed-width font where there is one, and a light
/// shade either way (a system without a monospace font draws it like the
/// rest of the text).
const CODE_OPEN: &str = r##"<span font_family="monospace" background="#808080" bgalpha="22%">"##;

/// Pango markup for one span of text: everything escaped, then `**bold**`,
/// `*italic*` and `` `code` `` (whose content is left as typed).
fn inline_markup(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    let mut bold = false;
    let mut italic = false;
    while let Some(c) = rest.chars().next() {
        if c == '`' {
            if let Some(end) = rest[1..].find('`') {
                let code = &rest[1..1 + end];
                out.push_str(CODE_OPEN);
                out.push_str(&glib::markup_escape_text(code));
                out.push_str("</span>");
                rest = &rest[end + 2..];
                continue;
            }
        }
        if rest.starts_with("**") && (bold || rest[2..].contains("**")) {
            out.push_str(if bold { "</b>" } else { "<b>" });
            bold = !bold;
            rest = &rest[2..];
            continue;
        }
        // A star opens italic when a word follows it and another star
        // closes it later ("5 * 3" and "2 ** 8" stay as typed).
        // (Only looked at on a star: slicing one byte on would cut a
        // character such as "ç" in two.)
        let opens_italic = || {
            let after = &rest[1..];
            after
                .chars()
                .next()
                .is_some_and(|next| next != '*' && !next.is_whitespace())
                && after.contains('*')
        };
        if c == '*' && (italic || opens_italic()) {
            out.push_str(if italic { "</i>" } else { "<i>" });
            italic = !italic;
            rest = &rest[1..];
            continue;
        }
        out.push_str(&glib::markup_escape_text(&c.to_string()));
        rest = &rest[c.len_utf8()..];
    }
    // A mark left open (a lone `**`) closes at the end of the span.
    if italic {
        out.push_str("</i>");
    }
    if bold {
        out.push_str("</b>");
    }
    out
}

fn text_label(markup: &str) -> gtk::Label {
    let label = cell_label(markup);
    label.set_wrap(true);
    label
}

/// A table cell: on one line. A wrapping label measured for the table's
/// scroller (any width) asked for the height of one letter per line.
fn cell_label(markup: &str) -> gtk::Label {
    let label = gtk::Label::builder()
        .use_markup(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .xalign(0.0)
        .selectable(true)
        .build();
    label.set_markup(markup);
    label
}

/// The note as shown on the details page.
pub fn view(notes: &str) -> gtk::Widget {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    for block in parse(notes) {
        match block {
            Block::Text(text) => {
                let markup = text
                    .lines()
                    .map(inline_markup)
                    .collect::<Vec<_>>()
                    .join("\n");
                root.append(&text_label(&markup));
            }
            Block::Code(code) => {
                let label = gtk::Label::builder()
                    .label(&code)
                    .xalign(0.0)
                    .selectable(true)
                    .build();
                label.add_css_class("monospace");
                let frame = gtk::Frame::builder().child(&label).build();
                frame.add_css_class("ashy-notes-code");
                root.append(&frame);
            }
            Block::Table { header, rows } => {
                let grid = gtk::Grid::builder()
                    .column_spacing(18)
                    .row_spacing(6)
                    .build();
                grid.add_css_class("ashy-notes-table");
                for (column, cell) in header.iter().enumerate() {
                    let label = cell_label(&format!("<b>{}</b>", inline_markup(cell)));
                    grid.attach(&label, column as i32, 0, 1, 1);
                }
                for (row, cells) in rows.iter().enumerate() {
                    for (column, cell) in cells.iter().enumerate() {
                        grid.attach(
                            &cell_label(&inline_markup(cell)),
                            column as i32,
                            row as i32 + 1,
                            1,
                            1,
                        );
                    }
                }
                // A wide table scrolls sideways instead of widening the page.
                let scrolled = gtk::ScrolledWindow::builder()
                    .vscrollbar_policy(gtk::PolicyType::Never)
                    .propagate_natural_height(true)
                    .vexpand(false)
                    .child(&grid)
                    .build();
                root.append(&scrolled);
            }
        }
    }
    root.upcast()
}

/// What a toolbar button puts in.
#[derive(Clone, Copy)]
enum Mark {
    Bold,
    Italic,
    Code,
    Table,
}

/// Wrap the selection in `mark` (or put the pair in and the cursor between
/// them); a table goes in on its own lines.
fn apply(view: &gtk::TextView, mark: Mark) {
    let buffer = view.buffer();
    let (open, close) = match mark {
        Mark::Bold => ("**", "**"),
        Mark::Italic => ("*", "*"),
        Mark::Code => ("`", "`"),
        Mark::Table => {
            let template = format!(
                "| {} | {} |\n| --- | --- |\n|  |  |\n",
                tr!("Column 1"),
                tr!("Column 2")
            );
            let mut at = buffer.iter_at_mark(&buffer.get_insert());
            if !at.starts_line() {
                buffer.insert(&mut at, "\n");
            }
            buffer.insert(&mut at, &template);
            view.grab_focus();
            return;
        }
    };
    if let Some((mut start, mut end)) = buffer.selection_bounds() {
        let text = buffer.text(&start, &end, false);
        buffer.delete(&mut start, &mut end);
        buffer.insert(&mut start, &format!("{open}{text}{close}"));
    } else {
        let mut at = buffer.iter_at_mark(&buffer.get_insert());
        buffer.insert(&mut at, &format!("{open}{close}"));
        at.backward_chars(close.chars().count() as i32);
        buffer.place_cursor(&at);
    }
    view.grab_focus();
}

/// The formatting buttons above a note being edited.
pub fn toolbar(view: &gtk::TextView) -> gtk::Box {
    let bar = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(2)
        .margin_bottom(4)
        .build();
    bar.add_css_class("toolbar");
    let buttons: [(Mark, Option<&str>, &str, &str); 4] = [
        (
            Mark::Bold,
            Some("format-text-bold-symbolic"),
            "",
            tr!("Bold (**text**)"),
        ),
        (
            Mark::Italic,
            Some("format-text-italic-symbolic"),
            "",
            tr!("Italic (*text*)"),
        ),
        (Mark::Code, None, "</>", tr!("Code (`text`)")),
        (
            Mark::Table,
            Some("view-grid-symbolic"),
            "",
            tr!("Insert a table"),
        ),
    ];
    for (mark, icon, text, tooltip) in buttons {
        let button = match icon {
            Some(icon) => gtk::Button::from_icon_name(icon),
            None => gtk::Button::with_label(text),
        };
        button.set_tooltip_text(Some(tooltip));
        button.update_property(&[gtk::accessible::Property::Label(tooltip)]);
        button.add_css_class("flat");
        if icon.is_none() {
            button.add_css_class("monospace");
        }
        let view = view.downgrade();
        button.connect_clicked(move |_| {
            if let Some(view) = view.upgrade() {
                apply(&view, mark);
            }
        });
        bar.append(&button);
    }
    let hint = gtk::Label::builder()
        .label(tr!("Shown formatted in the details"))
        .xalign(1.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();
    hint.add_css_class("caption");
    hint.add_css_class("dim-label");
    bar.append(&hint);
    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_marks_and_escaping() {
        assert_eq!(inline_markup("a **b** c"), "a <b>b</b> c");
        assert_eq!(
            inline_markup("*it* and `x<y`"),
            format!("<i>it</i> and {CODE_OPEN}x&lt;y</span>")
        );
        // Markup typed in a note is text, never markup.
        assert_eq!(inline_markup("<b>&"), "&lt;b&gt;&amp;");
        // A lone star or an unclosed mark stays as typed.
        assert_eq!(inline_markup("5 * 3"), "5 * 3");
        assert_eq!(inline_markup("2 ** 8"), "2 ** 8");
        // Code keeps its stars.
        assert_eq!(inline_markup("`**x**`"), format!("{CODE_OPEN}**x**</span>"));
        // Letters of more than one byte, marked or not.
        assert_eq!(
            inline_markup("Serviço **Ação** *pão*"),
            "Serviço <b>Ação</b> <i>pão</i>"
        );
        assert_eq!(inline_markup("ç*"), "ç*");
    }

    #[test]
    fn blocks_tables_and_code() {
        let note =
            "Server\n| Host | Port |\n| --- | --- |\n| db | 5432 |\n```\nssh root@x\n```\nend";
        assert_eq!(
            parse(note),
            vec![
                Block::Text("Server".into()),
                Block::Table {
                    header: vec!["Host".into(), "Port".into()],
                    rows: vec![vec!["db".into(), "5432".into()]],
                },
                Block::Code("ssh root@x".into()),
                Block::Text("end".into()),
            ]
        );
        // A line with bars but no separator under it is text.
        assert_eq!(
            parse("| not | a table |"),
            vec![Block::Text("| not | a table |".into())]
        );
        // Blank lines between blocks leave no empty paragraph.
        assert_eq!(
            parse("a\n\n```\nx\n```\n\nb"),
            vec![
                Block::Text("a".into()),
                Block::Code("x".into()),
                Block::Text("b".into())
            ]
        );
        // An unclosed fence runs to the end.
        assert_eq!(parse("```\nkey"), vec![Block::Code("key".into())]);
    }
}
