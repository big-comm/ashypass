//! Formatted notes: bold, italic, code, code blocks and tables.
//!
//! People see and edit the formatting itself: the entry form's editor
//! shows bold as bold and a table as a table, and the details page shows
//! the note the same way. In the vault a note stays plain text written
//! with Markdown's marks (`**bold**`, `*italic*`, `` `code` ``, fenced
//! blocks, `| a | b |` tables), so sync, backups, the browser extension
//! and the Android app keep reading it, and notes written before open
//! formatted. A `\` before `*`, `` ` `` or `\` keeps that mark as text.

use crate::tr;
use gtk::prelude::*;
use gtk::{gdk, glib};
use std::cell::Cell;
use std::rc::Rc;

// ============================================================================
// The stored form
// ============================================================================

/// A piece of a note.
#[derive(Debug, PartialEq, Eq)]
enum Block {
    /// Lines of text with inline marks.
    Text(String),
    /// A fenced ``` block.
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

/// How a run of text looks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Style {
    bold: bool,
    italic: bool,
    code: bool,
}

/// One line's runs of text, each with its style: `**bold**`, `*italic*`
/// and `` `code` `` (whose content is taken as typed). A lone star or an
/// unclosed mark stays text ("5 * 3", "2 ** 8").
fn inline_spans(line: &str) -> Vec<(String, Style)> {
    let mut spans: Vec<(String, Style)> = Vec::new();
    let mut style = Style::default();
    let mut current = String::new();
    let push = |spans: &mut Vec<(String, Style)>, text: &mut String, style: Style| {
        if text.is_empty() {
            return;
        }
        match spans.last_mut() {
            Some((last, last_style)) if *last_style == style => last.push_str(text),
            _ => spans.push((text.clone(), style)),
        }
        text.clear();
    };
    let mut rest = line;
    while let Some(c) = rest.chars().next() {
        // Only ever sliced past an ASCII mark: one byte on would cut a
        // letter such as "ç" in two.
        if c == '\\' {
            if let Some(next) = rest[1..].chars().next().filter(|n| "*`\\".contains(*n)) {
                current.push(next);
                rest = &rest[1 + next.len_utf8()..];
                continue;
            }
        }
        if c == '`' {
            if let Some(end) = rest[1..].find('`') {
                push(&mut spans, &mut current, style);
                let mut code = rest[1..1 + end].to_string();
                push(
                    &mut spans,
                    &mut code,
                    Style {
                        code: true,
                        ..style
                    },
                );
                rest = &rest[end + 2..];
                continue;
            }
        }
        if rest.starts_with("**") && (style.bold || rest[2..].contains("**")) {
            push(&mut spans, &mut current, style);
            style.bold = !style.bold;
            rest = &rest[2..];
            continue;
        }
        if c == '*' {
            let after = &rest[1..];
            let opens = after
                .chars()
                .next()
                .is_some_and(|next| next != '*' && !next.is_whitespace())
                && after.contains('*');
            if style.italic || opens {
                push(&mut spans, &mut current, style);
                style.italic = !style.italic;
                rest = after;
                continue;
            }
        }
        current.push(c);
        rest = &rest[c.len_utf8()..];
    }
    push(&mut spans, &mut current, style);
    spans
}

/// Text of a run in the stored form: marks typed as text get a `\`.
fn escape_marks(text: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = text.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        match c {
            '*' | '`' => {
                out.push('\\');
                out.push(*c);
            }
            // A backslash only matters before a mark (or another one).
            '\\' if chars.get(i + 1).is_some_and(|n| "*`\\".contains(*n)) => out.push_str("\\\\"),
            c => out.push(*c),
        }
    }
    out
}

/// One line back to the stored form. Spaces at the edges of a run go
/// outside its marks, where they cannot keep a mark from being read.
fn spans_to_markdown(spans: &[(String, Style)]) -> String {
    let mut out = String::new();
    for (text, style) in spans {
        let core = text.trim();
        if core.is_empty() || *style == Style::default() {
            out.push_str(&escape_marks(text));
            continue;
        }
        let lead = &text[..text.len() - text.trim_start().len()];
        let trail = &text[text.trim_end().len()..];
        out.push_str(lead);
        let mut marked = if style.code {
            // Code is taken as typed: a backtick cannot sit inside it.
            format!("`{}`", core.replace('`', "'"))
        } else {
            escape_marks(core)
        };
        if style.italic {
            marked = format!("*{marked}*");
        }
        if style.bold {
            marked = format!("**{marked}**");
        }
        out.push_str(&marked);
        out.push_str(trail);
    }
    out
}

fn table_markdown(header: &[String], rows: &[Vec<String>]) -> String {
    let line = |cells: &[String]| {
        let cells: Vec<String> = cells.iter().map(|c| c.replace('|', "/")).collect();
        format!("| {} |", cells.join(" | "))
    };
    let mut out = vec![
        line(header),
        line(&vec!["---".to_string(); header.len().max(1)]),
    ];
    out.extend(rows.iter().map(|row| line(row)));
    out.join("\n")
}

// ============================================================================
// Shown
// ============================================================================

/// Code in a line: a fixed-width font where there is one, and a light
/// shade either way (a system without a monospace font draws it like the
/// rest of the text).
const CODE_OPEN: &str = r##"<span font_family="monospace" background="#808080" bgalpha="22%">"##;

/// Pango markup for one line: everything escaped, each run wrapped whole.
fn inline_markup(line: &str) -> String {
    let mut out = String::new();
    for (text, style) in inline_spans(line) {
        let mut piece = glib::markup_escape_text(&text).to_string();
        if style.code {
            piece = format!("{CODE_OPEN}{piece}</span>");
        }
        if style.italic {
            piece = format!("<i>{piece}</i>");
        }
        if style.bold {
            piece = format!("<b>{piece}</b>");
        }
        out.push_str(&piece);
    }
    out
}

fn label(markup: &str, wrap: bool) -> gtk::Label {
    let label = gtk::Label::builder()
        .use_markup(true)
        .wrap(wrap)
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
                root.append(&label(&markup, true));
            }
            Block::Code(code) => {
                let code = gtk::Label::builder()
                    .label(&code)
                    .xalign(0.0)
                    .selectable(true)
                    .build();
                code.add_css_class("monospace");
                let frame = gtk::Frame::builder().child(&code).build();
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
                    // Cells on one line: a wrapping label measured for the
                    // scroller (any width) asks for one letter per line.
                    let cell = label(&format!("<b>{}</b>", inline_markup(cell)), false);
                    grid.attach(&cell, column as i32, 0, 1, 1);
                }
                for (row, cells) in rows.iter().enumerate() {
                    for (column, cell) in cells.iter().enumerate() {
                        grid.attach(
                            &label(&inline_markup(cell), false),
                            column as i32,
                            row as i32 + 1,
                            1,
                            1,
                        );
                    }
                }
                // A wide table scrolls sideways instead of widening the page.
                root.append(
                    &gtk::ScrolledWindow::builder()
                        .vscrollbar_policy(gtk::PolicyType::Never)
                        .propagate_natural_height(true)
                        .vexpand(false)
                        .child(&grid)
                        .build(),
                );
            }
        }
    }
    root.upcast()
}

// ============================================================================
// Edited
// ============================================================================

/// The tags of the editor's buffer.
#[derive(Clone)]
struct Tags {
    bold: gtk::TextTag,
    italic: gtk::TextTag,
    code: gtk::TextTag,
    /// Lines of a fenced code block.
    block: gtk::TextTag,
}

impl Tags {
    fn new(buffer: &gtk::TextBuffer) -> Self {
        let shade = gdk::RGBA::new(0.5, 0.5, 0.5, 0.22);
        let tags = Self {
            bold: gtk::TextTag::builder().name("bold").weight(700).build(),
            italic: gtk::TextTag::builder()
                .name("italic")
                .style(gtk::pango::Style::Italic)
                .build(),
            code: gtk::TextTag::builder()
                .name("code")
                .family("monospace")
                .background_rgba(&shade)
                .build(),
            block: gtk::TextTag::builder()
                .name("block")
                .family("monospace")
                .paragraph_background_rgba(&shade)
                .build(),
        };
        let table = buffer.tag_table();
        for tag in [&tags.bold, &tags.italic, &tags.code, &tags.block] {
            table.add(tag);
        }
        tags
    }

    fn style_at(&self, iter: &gtk::TextIter) -> Style {
        Style {
            bold: iter.has_tag(&self.bold),
            italic: iter.has_tag(&self.italic),
            code: iter.has_tag(&self.code),
        }
    }

    /// The style new text at `iter` takes: that of the letter before it.
    fn style_before(&self, iter: &gtk::TextIter) -> Style {
        let mut before = *iter;
        if before.backward_char() && before.child_anchor().is_none() && before.char() != '\n' {
            self.style_at(&before)
        } else {
            Style::default()
        }
    }

    fn set_style(
        &self,
        buffer: &gtk::TextBuffer,
        start: &gtk::TextIter,
        end: &gtk::TextIter,
        style: Style,
    ) {
        for (tag, on) in [
            (&self.bold, style.bold),
            (&self.italic, style.italic),
            (&self.code, style.code),
        ] {
            if on {
                buffer.apply_tag(tag, start, end);
            } else {
                buffer.remove_tag(tag, start, end);
            }
        }
    }
}

/// A table inside the editor: a grid of fields, a header row on top, and
/// buttons to add a row, a column, or remove it.
fn table_widget(
    view: &gtk::TextView,
    anchor: &gtk::TextChildAnchor,
    header: &[String],
    rows: &[Vec<String>],
) -> gtk::Widget {
    let columns = header
        .len()
        .max(rows.iter().map(Vec::len).max().unwrap_or(0))
        .max(1);
    let grid = gtk::Grid::builder()
        .column_spacing(4)
        .row_spacing(4)
        .build();
    grid.set_widget_name(TABLE_GRID);
    let cell = |text: &str, header_row: bool| {
        let entry = gtk::Entry::builder().text(text).width_chars(12).build();
        if header_row {
            entry.add_css_class("ashy-notes-header-cell");
        }
        entry
    };
    for column in 0..columns {
        let text = header.get(column).map(String::as_str).unwrap_or("");
        grid.attach(&cell(text, true), column as i32, 0, 1, 1);
    }
    for (row, cells) in rows.iter().enumerate() {
        for column in 0..columns {
            let text = cells.get(column).map(String::as_str).unwrap_or("");
            grid.attach(&cell(text, false), column as i32, row as i32 + 1, 1, 1);
        }
    }

    let actions = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(4)
        .build();
    let button = |icon: &str, text: &str| {
        let button = gtk::Button::builder()
            .child(
                &adw::ButtonContent::builder()
                    .icon_name(icon)
                    .label(text)
                    .build(),
            )
            .build();
        button.add_css_class("flat");
        button.add_css_class("caption");
        button
    };
    let add_row = button("list-add-symbolic", tr!("Row"));
    let add_column = button("list-add-symbolic", tr!("Column"));
    let remove = button("user-trash-symbolic", tr!("Remove table"));
    actions.append(&add_row);
    actions.append(&add_column);
    actions.append(&remove);
    {
        let grid = grid.downgrade();
        add_row.connect_clicked(move |_| {
            let Some(grid) = grid.upgrade() else { return };
            let (columns, rows) = grid_size(&grid);
            for column in 0..columns {
                grid.attach(&cell("", false), column, rows, 1, 1);
            }
        });
    }
    {
        let grid = grid.downgrade();
        add_column.connect_clicked(move |_| {
            let Some(grid) = grid.upgrade() else { return };
            let (columns, rows) = grid_size(&grid);
            for row in 0..rows {
                grid.attach(&cell("", row == 0), columns, row, 1, 1);
            }
        });
    }
    {
        // Weak both: the table sits in the buffer the anchor belongs to.
        let view = view.downgrade();
        let anchor = anchor.downgrade();
        remove.connect_clicked(move |_| {
            let (Some(view), Some(anchor)) = (view.upgrade(), anchor.upgrade()) else {
                return;
            };
            let buffer = view.buffer();
            let mut start = buffer.iter_at_child_anchor(&anchor);
            let mut end = start;
            end.forward_char();
            buffer.delete(&mut start, &mut end);
            view.grab_focus();
        });
    }

    let table = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .margin_top(4)
        .margin_bottom(4)
        .build();
    table.add_css_class("ashy-notes-table-editor");
    table.append(&grid);
    table.append(&actions);
    table.upcast()
}

const TABLE_GRID: &str = "ashy-notes-table-grid";

/// Columns and rows of a table's grid of fields.
fn grid_size(grid: &gtk::Grid) -> (i32, i32) {
    let mut columns = 0;
    while grid.child_at(columns, 0).is_some() {
        columns += 1;
    }
    let mut rows = 0;
    while grid.child_at(0, rows).is_some() {
        rows += 1;
    }
    (columns, rows)
}

/// The cells of the table widget at `anchor`, header row first.
fn table_cells_at(anchor: &gtk::TextChildAnchor) -> Option<Vec<Vec<String>>> {
    let table = anchor.widgets().into_iter().next()?;
    let grid = table.first_child()?.downcast::<gtk::Grid>().ok()?;
    let (columns, rows) = grid_size(&grid);
    Some(
        (0..rows)
            .map(|row| {
                (0..columns)
                    .map(|column| {
                        grid.child_at(column, row)
                            .and_downcast::<gtk::Entry>()
                            .map(|entry| entry.text().trim().to_string())
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .collect(),
    )
}

/// The rich editor of a note.
pub struct NotesEditor {
    pub root: gtk::Box,
    view: gtk::TextView,
    tags: Tags,
}

impl NotesEditor {
    pub fn new(notes: &str) -> Rc<Self> {
        let view = gtk::TextView::builder()
            .wrap_mode(gtk::WrapMode::WordChar)
            .accepts_tab(false)
            .top_margin(10)
            .bottom_margin(10)
            .left_margin(12)
            .right_margin(12)
            .height_request(120)
            .build();
        view.add_css_class("ashy-notes");
        view.update_property(&[gtk::accessible::Property::Label(tr!("Notes"))]);
        let buffer = view.buffer();
        let tags = Tags::new(&buffer);

        let toolbar = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(2)
            .margin_bottom(4)
            .build();
        toolbar.add_css_class("toolbar");
        let toggle = |icon: Option<&str>, text: &str, tooltip: &str| {
            let button = gtk::ToggleButton::builder().tooltip_text(tooltip).build();
            match icon {
                Some(icon) => button.set_icon_name(icon),
                None => {
                    button.set_label(text);
                    button.add_css_class("monospace");
                }
            }
            button.add_css_class("flat");
            button.update_property(&[gtk::accessible::Property::Label(tooltip)]);
            toolbar.append(&button);
            button
        };
        let bold = toggle(Some("format-text-bold-symbolic"), "", tr!("Bold (Ctrl+B)"));
        let italic = toggle(
            Some("format-text-italic-symbolic"),
            "",
            tr!("Italic (Ctrl+I)"),
        );
        let code = toggle(None, "</>", tr!("Code"));
        let table = gtk::Button::builder()
            .icon_name("view-grid-symbolic")
            .tooltip_text(tr!("Insert a table"))
            .build();
        table.add_css_class("flat");
        table.update_property(&[gtk::accessible::Property::Label(tr!("Insert a table"))]);
        toolbar.append(&table);

        let frame = gtk::Frame::builder().child(&view).build();
        frame.add_css_class("view");
        let root = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        root.append(&toolbar);
        root.append(&frame);

        let editor = Rc::new(Self { root, view, tags });
        editor.load(notes);
        editor.wire(&bold, &italic, &code, &table);
        editor
    }

    /// Fill the buffer from the stored form.
    fn load(&self, notes: &str) {
        let buffer = self.view.buffer();
        let mut end = buffer.end_iter();
        let mut first = true;
        for block in parse(notes) {
            if !first {
                buffer.insert(&mut end, "\n");
            }
            first = false;
            match block {
                Block::Text(text) => {
                    for (i, line) in text.lines().enumerate() {
                        if i > 0 {
                            buffer.insert(&mut end, "\n");
                        }
                        for (run, style) in inline_spans(line) {
                            let offset = end.offset();
                            buffer.insert(&mut end, &run);
                            let start = buffer.iter_at_offset(offset);
                            self.tags.set_style(&buffer, &start, &end, style);
                        }
                    }
                }
                Block::Code(code) => {
                    let offset = end.offset();
                    buffer.insert(&mut end, &code);
                    let start = buffer.iter_at_offset(offset);
                    buffer.apply_tag(&self.tags.block, &start, &end);
                }
                Block::Table { header, rows } => {
                    self.insert_table(&mut end, &header, &rows);
                }
            }
        }
        buffer.place_cursor(&buffer.end_iter());
    }

    fn insert_table(&self, at: &mut gtk::TextIter, header: &[String], rows: &[Vec<String>]) {
        let buffer = self.view.buffer();
        let anchor = buffer.create_child_anchor(at);
        let widget = table_widget(&self.view, &anchor, header, rows);
        self.view.add_child_at_anchor(&widget, &anchor);
    }

    /// The note in its stored form.
    pub fn markdown(&self) -> String {
        let buffer = self.view.buffer();
        let mut out: Vec<String> = Vec::new();
        let mut line: Vec<(String, Style)> = Vec::new();
        let mut block: Option<Vec<String>> = None;
        let mut block_line = String::new();
        let flush_line = |line: &mut Vec<(String, Style)>, out: &mut Vec<String>| {
            out.push(spans_to_markdown(line));
            line.clear();
        };
        let mut iter = buffer.start_iter();
        while !iter.is_end() {
            if let Some(anchor) = iter.child_anchor() {
                if !line.is_empty() {
                    flush_line(&mut line, &mut out);
                }
                if let Some(cells) = table_cells_at(&anchor) {
                    if let Some((header, rows)) = cells.split_first() {
                        out.push(table_markdown(header, rows));
                    }
                }
                iter.forward_char();
                // The line break after a table is part of it.
                if iter.char() == '\n' {
                    iter.forward_char();
                }
                continue;
            }
            let c = iter.char();
            let in_block = iter.has_tag(&self.tags.block);
            match (&mut block, in_block) {
                (None, true) => {
                    if !line.is_empty() {
                        flush_line(&mut line, &mut out);
                    }
                    block = Some(Vec::new());
                }
                (Some(lines), false) => {
                    lines.push(std::mem::take(&mut block_line));
                    out.push(format!("```\n{}\n```", lines.join("\n")));
                    block = None;
                }
                _ => {}
            }
            if let Some(lines) = block.as_mut() {
                if c == '\n' {
                    lines.push(std::mem::take(&mut block_line));
                } else {
                    block_line.push(c);
                }
            } else if c == '\n' {
                flush_line(&mut line, &mut out);
            } else {
                let style = self.tags.style_at(&iter);
                match line.last_mut() {
                    Some((text, last)) if *last == style => text.push(c),
                    _ => line.push((c.to_string(), style)),
                }
            }
            iter.forward_char();
        }
        if let Some(mut lines) = block {
            lines.push(block_line);
            out.push(format!("```\n{}\n```", lines.join("\n")));
        } else if !line.is_empty() {
            flush_line(&mut line, &mut out);
        }
        out.join("\n").trim().to_string()
    }

    fn wire(
        self: &Rc<Self>,
        bold: &gtk::ToggleButton,
        italic: &gtk::ToggleButton,
        code: &gtk::ToggleButton,
        table: &gtk::Button,
    ) {
        let buffer = self.view.buffer();
        // What the next typed letters look like: set by the buttons, until
        // the cursor goes elsewhere; else the letter before the cursor's.
        let chosen: Rc<Cell<Option<Style>>> = Rc::new(Cell::new(None));
        let typed_to: Rc<Cell<i32>> = Rc::new(Cell::new(-1));
        // Set while the buttons follow the cursor, so they apply nothing.
        let syncing: Rc<Cell<bool>> = Rc::new(Cell::new(false));

        {
            let tags = self.tags.clone();
            let chosen = chosen.clone();
            let typed_to = typed_to.clone();
            buffer.connect_closure(
                "insert-text",
                true,
                glib::closure_local!(move |buffer: gtk::TextBuffer,
                                           end: gtk::TextIter,
                                           text: &str,
                                           _len: i32| {
                    let mut start = end;
                    start.backward_chars(text.chars().count() as i32);
                    if !start.has_tag(&tags.block) {
                        let style = chosen.get().unwrap_or_else(|| tags.style_before(&start));
                        tags.set_style(&buffer, &start, &end, style);
                    }
                    typed_to.set(end.offset());
                }),
            );
        }

        let buttons = [bold.downgrade(), italic.downgrade(), code.downgrade()];
        let sync_buttons = {
            let tags = self.tags.clone();
            let chosen = chosen.clone();
            let syncing = syncing.clone();
            let buttons = buttons.clone();
            move |buffer: &gtk::TextBuffer| {
                let cursor = buffer.iter_at_mark(&buffer.get_insert());
                let style = chosen
                    .get()
                    .unwrap_or_else(|| match buffer.selection_bounds() {
                        Some((start, _)) => tags.style_at(&start),
                        None => tags.style_before(&cursor),
                    });
                syncing.set(true);
                for (button, on) in buttons.iter().zip([style.bold, style.italic, style.code]) {
                    if let Some(button) = button.upgrade() {
                        button.set_active(on);
                    }
                }
                syncing.set(false);
            }
        };
        {
            let chosen = chosen.clone();
            let typed_to = typed_to.clone();
            let sync_buttons = sync_buttons.clone();
            buffer.connect_mark_set(move |buffer, location, mark| {
                if mark.name().as_deref() != Some("insert") {
                    return;
                }
                // Moved elsewhere (not by typing): forget the chosen style.
                if location.offset() != typed_to.get() {
                    chosen.set(None);
                }
                sync_buttons(buffer);
            });
        }

        for (index, button) in [bold, italic, code].into_iter().enumerate() {
            let tags = self.tags.clone();
            let chosen = chosen.clone();
            let syncing = syncing.clone();
            let view = self.view.downgrade();
            button.connect_toggled(move |button| {
                if syncing.get() {
                    return;
                }
                let Some(view) = view.upgrade() else { return };
                let buffer = view.buffer();
                let on = button.is_active();
                let tag = [&tags.bold, &tags.italic, &tags.code][index];
                if let Some((start, end)) = buffer.selection_bounds() {
                    if on {
                        buffer.apply_tag(tag, &start, &end);
                    } else {
                        buffer.remove_tag(tag, &start, &end);
                    }
                } else {
                    let cursor = buffer.iter_at_mark(&buffer.get_insert());
                    let mut style = chosen.get().unwrap_or_else(|| tags.style_before(&cursor));
                    match index {
                        0 => style.bold = on,
                        1 => style.italic = on,
                        _ => style.code = on,
                    }
                    chosen.set(Some(style));
                }
                view.grab_focus();
            });
        }

        {
            let editor = Rc::downgrade(self);
            table.connect_clicked(move |_| {
                let Some(editor) = editor.upgrade() else {
                    return;
                };
                let buffer = editor.view.buffer();
                let mut at = buffer.iter_at_mark(&buffer.get_insert());
                if !at.starts_line() {
                    buffer.insert(&mut at, "\n");
                }
                editor.insert_table(
                    &mut at,
                    &[tr!("Column 1").to_string(), tr!("Column 2").to_string()],
                    &[vec![String::new(), String::new()]],
                );
                buffer.insert(&mut at, "\n");
                buffer.place_cursor(&at);
                editor.view.grab_focus();
            });
        }

        // Ctrl+B and Ctrl+I while writing (before the window's own
        // shortcuts, which use Ctrl+B for copying a user).
        let keys = gtk::EventControllerKey::new();
        keys.set_propagation_phase(gtk::PropagationPhase::Capture);
        {
            let buttons = buttons.clone();
            keys.connect_key_pressed(move |_, key, _, modifiers| {
                let only_ctrl = modifiers
                    & (gdk::ModifierType::CONTROL_MASK
                        | gdk::ModifierType::SHIFT_MASK
                        | gdk::ModifierType::ALT_MASK
                        | gdk::ModifierType::SUPER_MASK)
                    == gdk::ModifierType::CONTROL_MASK;
                let index = match key.to_lower() {
                    gdk::Key::b if only_ctrl => 0,
                    gdk::Key::i if only_ctrl => 1,
                    _ => return glib::Propagation::Proceed,
                };
                if let Some(button) = buttons[index].upgrade() {
                    button.set_active(!button.is_active());
                }
                glib::Propagation::Stop
            });
        }
        self.view.add_controller(keys);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(text: &str) -> (String, Style) {
        (text.into(), Style::default())
    }

    #[test]
    fn inline_marks_and_escaping() {
        let bold = Style {
            bold: true,
            ..Style::default()
        };
        assert_eq!(
            inline_spans("a **b** c"),
            vec![plain("a "), ("b".into(), bold), plain(" c")]
        );
        // Markup typed in a note is text, never markup.
        assert_eq!(inline_markup("<b>&"), "&lt;b&gt;&amp;");
        assert_eq!(
            inline_markup("*it* and `x<y`"),
            format!("<i>it</i> and {CODE_OPEN}x&lt;y</span>")
        );
        // A lone star or an unclosed mark stays as typed.
        assert_eq!(inline_markup("5 * 3"), "5 * 3");
        assert_eq!(inline_markup("2 ** 8"), "2 ** 8");
        // Code keeps its stars; a backslash keeps a mark as text.
        assert_eq!(inline_markup("`**x**`"), format!("{CODE_OPEN}**x**</span>"));
        assert_eq!(inline_markup(r"\*not italic\*"), "*not italic*");
        // Letters of more than one byte, marked or not.
        assert_eq!(
            inline_markup("Serviço **Ação** *pão*"),
            "Serviço <b>Ação</b> <i>pão</i>"
        );
        assert_eq!(inline_markup("ç*"), "ç*");
        // Bold and italic together nest properly.
        assert_eq!(inline_markup("***x***"), "<b><i>x</i></b>");
    }

    #[test]
    fn styled_runs_survive_the_stored_form() {
        let style = |bold, italic, code| Style { bold, italic, code };
        let runs = vec![
            plain("Server "),
            ("AshyTV ".into(), style(true, false, false)),
            plain("at "),
            ("5 * 3 ".into(), style(false, true, false)),
            ("ssh root@x".into(), style(false, false, true)),
            plain(r" C:\path and `ticks` *stars*"),
        ];
        let stored = spans_to_markdown(&runs);
        let read = inline_spans(&stored);
        let text: String = read.iter().map(|(t, _)| t.as_str()).collect();
        let original: String = runs.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(text, original, "stored: {stored}");
        assert!(read.contains(&("AshyTV".into(), style(true, false, false))));
        assert!(read.contains(&("5 * 3".into(), style(false, true, false))));
        assert!(read.contains(&("ssh root@x".into(), style(false, false, true))));
        assert!(read
            .iter()
            .any(|(t, s)| t.contains("`ticks` *stars*") && *s == Style::default()));
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
        assert_eq!(
            parse("| not | a table |"),
            vec![Block::Text("| not | a table |".into())]
        );
        assert_eq!(parse("```\nkey"), vec![Block::Code("key".into())]);
        assert_eq!(
            parse("a\n\n```\nx\n```\n\nb"),
            vec![
                Block::Text("a".into()),
                Block::Code("x".into()),
                Block::Text("b".into())
            ]
        );
        assert_eq!(
            table_markdown(&["A".into(), "B".into()], &[vec!["1".into(), "x|y".into()]]),
            "| A | B |\n| --- | --- |\n| 1 | x/y |"
        );
    }
}
