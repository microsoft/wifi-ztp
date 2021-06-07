
#ifndef __ZTPD_UI_H__
#define __ZTPD_UI_H__

struct ztpd;

/**
 * @brief Activates the ui service.
 *
 * @param ztpd The global ztpd instance.
 * @return int
 */
int
ztpd_ui_activate(struct ztpd *ztpd);

/**
 * @brief Deactivates the ui service.
 *
 * @param ztpd The global ztpd instance.
 * @return int
 */
int
ztpd_ui_deactivate(struct ztpd *ztpd);

#endif //__ZTPD_UI_H__
