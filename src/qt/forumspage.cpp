#include "forumspage.h"
#include "ui_forumspage.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "util.h"
#include <QDesktopServices>

using namespace GUIUtil;

ForumsPage::ForumsPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ForumsPage),
    walletModel(0)
{
    ui->setupUi(this);
    ui->textEdit->setFont(qFontLargerBold);
    // Setup header and styles
    if (fNoHeaders)
        GUIUtil::header(this, QString(""));
    else
        GUIUtil::header(this, QString(":images/headerForums"));
    this->layout()->setContentsMargins(0, HEADER_HEIGHT, 0, 0);

}

ForumsPage::~ForumsPage()
{
    delete ui;
}

void ForumsPage::setModel(WalletModel *model)
{
    this->walletModel = model;
}

void ForumsPage::on_explorerButton_clicked()
{
    QDesktopServices::openUrl(QUrl("https://chainz.cryptoid.info/vrc/"));
}

void ForumsPage::on_chatButton_clicked()
{
    QDesktopServices::openUrl(QUrl("https://slackin-idqpjecyzv.now.sh/"));
}

void ForumsPage::on_forumButton_clicked()
{
    QDesktopServices::openUrl(QUrl("https://bitcointalk.org/index.php?topic=2385158.0"));
}

void ForumsPage::on_siteButton_clicked()
{
    QDesktopServices::openUrl(QUrl("http://www.vericoin.info"));
}
