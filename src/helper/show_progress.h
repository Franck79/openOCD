#ifndef _SHOW_PROGRESS_H
#define _SHOW_PROGRESS_H

void inc_progress(int val);
int show_progress(void *dummy);
void init_progression_bar(int max);
void stop_progression_bar(void);

#endif
