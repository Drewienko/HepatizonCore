#include "TitleBar.hpp"

namespace
{
constexpr int g_barHeight = 40;
constexpr int g_buttonSize = 40;
constexpr int g_leftMargin = 10;
} // namespace

TitleBar::TitleBar(QWidget* parent) : QWidget(parent)
{
    setFixedHeight(g_barHeight);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(g_leftMargin, 0, 0, 0);

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_titleLabel = new QLabel("HEPATIZON", this);
    m_titleLabel->setObjectName("TitleLabel");

    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    m_closeBtn = new QPushButton("X", this);
    m_closeBtn->setFixedSize(g_buttonSize, g_buttonSize);
    m_closeBtn->setObjectName("CloseButton");
    m_closeBtn->setCursor(Qt::PointingHandCursor);

    layout->addWidget(m_titleLabel);
    layout->addStretch();
    layout->addWidget(m_closeBtn);

    connect(m_closeBtn, &QPushButton::clicked, this, &TitleBar::closeClicked);
}