#ifndef SRC_UI_GUI_COMPONENTS_HPP_TITLEBAR_HPP
#define SRC_UI_GUI_COMPONENTS_HPP_TITLEBAR_HPP

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QWidget>

class TitleBar : public QWidget
{
    Q_OBJECT
public:
    explicit TitleBar(QWidget* parent = nullptr);

signals:
    void closeClicked();

private:
    QLabel* m_titleLabel;
    QPushButton* m_closeBtn;
};

#endif // SRC_UI_GUI_COMPONENTS_HPP_TITLEBAR_HPP