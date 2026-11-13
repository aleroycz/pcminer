// SPDX-License-Identifier: GPL-3.0-or-later
//
// ratatui dashboard: status, pairing, telemetry tiles, event log.
//
// Copyright (C) 2026 Vakea

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::{fmt_hashrate, AppState, Phase};

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;

pub fn draw(f: &mut Frame, s: &AppState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(4), // identity / connection
            Constraint::Length(6), // tiles
            Constraint::Min(5),    // log
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_header(f, root[0], s);
    draw_identity(f, root[1], s);
    draw_tiles(f, root[2], s);
    draw_log(f, root[3], s);
    draw_footer(f, root[4]);
}

fn phase_style(p: &Phase) -> Style {
    let c = match p {
        Phase::Mining => Color::Green,
        Phase::Connecting | Phase::Discovering | Phase::WaitingPair => Color::Yellow,
        Phase::Paused => Color::Magenta,
        Phase::Error => Color::Red,
        Phase::Idle => Color::Gray,
    };
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}

fn draw_header(f: &mut Frame, area: Rect, s: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let line = Line::from(vec![
        Span::styled(
            "  MicroMiner ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("· PC Worker", Style::default().fg(Color::White)),
        Span::raw("    "),
        Span::styled(format!("[ {} ]", s.phase.label()), phase_style(&s.phase)),
        Span::raw("  "),
        Span::styled(
            truncate(&s.status_detail, inner.width.saturating_sub(40) as usize),
            Style::default().fg(MUTED),
        ),
    ]);
    f.render_widget(Paragraph::new(line), inner);
}

fn draw_identity(f: &mut Frame, area: Rect, s: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED))
        .title(Span::styled(" connection ", Style::default().fg(MUTED)));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let phone = if s.device_name.is_empty() {
        "— not connected —".to_string()
    } else {
        format!("{}  [{}]", s.device_name, s.device_fp)
    };
    let armed = if s.armed {
        Span::styled(
            "armed",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("disarmed", Style::default().fg(Color::Gray))
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  phone    ", Style::default().fg(MUTED)),
            Span::styled(phone, Style::default().fg(Color::White)),
            Span::raw("   "),
            Span::styled("miner ", Style::default().fg(MUTED)),
            armed,
        ]),
        Line::from(vec![
            Span::styled("  this PC  ", Style::default().fg(MUTED)),
            Span::styled(
                format!("worker key [{}]", s.my_fp),
                Style::default().fg(Color::White),
            ),
            Span::raw("   "),
            Span::styled("cpu lanes ", Style::default().fg(MUTED)),
            Span::styled(s.threads.to_string(), Style::default().fg(Color::White)),
            Span::raw("   "),
            Span::styled(
                {
                    let up = s.started.elapsed().as_secs();
                    format!("up {:02}:{:02}:{:02}", up / 3600, (up / 60) % 60, up % 60)
                },
                Style::default().fg(MUTED),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_tiles(f: &mut Frame, area: Rect, s: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    tile(
        f,
        cols[0],
        "hashrate",
        &fmt_hashrate(s.hashrate),
        Color::Green,
    );
    tile(f, cols[1], "backend", &s.backend, ACCENT);
    tile(
        f,
        cols[2],
        "shares (ok/found)",
        &format!("{} / {}", s.accepted, s.found),
        Color::Green,
    );
    let temp = if s.gpu_temp_c >= 0 {
        let fan = if s.gpu_fan_pct >= 0 {
            format!(" {}%fan", s.gpu_fan_pct)
        } else {
            String::new()
        };
        format!("{}°C {}{}", s.gpu_temp_c, s.thermal_band, fan)
    } else {
        format!("— ({})", s.thermal_band)
    };
    let temp_color = match s.thermal_band.as_str() {
        "critical" | "hot" => Color::Red,
        "warm" => Color::Yellow,
        _ => Color::White,
    };
    tile(f, cols[3], "gpu temp", &temp, temp_color);

    // Second visual line inside the tiles area is handled by each tile's body.
    let _ = s.rejected;
    let _ = s.stale;
    let _ = s.total_hashes;
}

fn tile(f: &mut Frame, area: Rect, label: &str, value: &str, value_color: Color) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(Span::styled(
            format!(" {label}"),
            Style::default().fg(MUTED),
        )),
        Line::from(Span::styled(
            format!(" {value}"),
            Style::default()
                .fg(value_color)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_log(f: &mut Frame, area: Rect, s: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED))
        .title(Span::styled(" activity ", Style::default().fg(MUTED)));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = inner.height as usize;
    let start = s.log.len().saturating_sub(rows);
    let lines: Vec<Line> = s
        .log
        .iter()
        .skip(start)
        .map(|l| {
            Line::from(Span::styled(
                format!(" {l}"),
                Style::default().fg(Color::Gray),
            ))
        })
        .collect();
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            "  q",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" quit   ", Style::default().fg(MUTED)),
        Span::styled(
            "p",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" pause/resume   ", Style::default().fg(MUTED)),
        Span::styled(
            "r",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" rescan LAN", Style::default().fg(MUTED)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn truncate(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
