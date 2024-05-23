# performance evaluation for lightcross and smartbugs when analysing the smartbugs dataset
source("packages.R")
source("configuration.R")
source("functions.R")
categories<-c("access_control", "arithmetic", "bad_randomness", "denial_of_service", "front_running", "other", "reentrancy", "short_addresses", "time_manipulation", "unchecked_low_level_call
s")
lightcross_path <- "../../DATA/lightcross/access_control"
smartbugs_path <- "../../DATA/smartbugs/access_control"
figures_path <- "../../figures/"

light_csvs <- retrieve_all_csv_files(lightcross_path)
smartbugs_csvs<-retrieve_all_csv_files(smartbugs_path)

light_csvs$filename <-basename(light_csvs$File)

light_csvs_df <- data.frame(contract = light_csvs$filename, execution_time = light_csvs$Execution.time, scanner = light_csvs$Tool)
df_lightcross <- bind_rows(light_csvs_df, .id="expID")
df_lightcross['Tool'] ='lightcross'

smartbugs_csvs$toolid<- ifelse(smartbugs_csvs$toolid == "mythril-0.24.7", "mythril", smartbugs_csvs$toolid)

smartbugs_csvs_df <-data_frame(contract = smartbugs_csvs$basename,execution_time =smartbugs_csvs$duration, scanner = smartbugs_csvs$toolid)
df_smartbugs <- bind_rows(smartbugs_csvs_df, .id="expID")
df_smartbugs['Tool'] ='smartbugs'
perfData<- rbind(df_lightcross, df_smartbugs)
perfData<- subset(perfData, execution_time <= 4000)

# limit rows to 100
# perfData<-head(perfData, n = 400)

ggplot(perfData, aes(x = contract, y = execution_time, fill = Tool)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))
ggsave("tools-barplot_access_control.pdf", path = "figures/")

perfData_slither <- subset(perfData, scanner == "slither")
ggplot(perfData_slither, aes(x = contract, y = execution_time, fill = Tool)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

ggsave("slither-barplot_access_control.pdf", path = "figures/")

perfData_mythril <- subset(perfData, scanner == "mythril")
ggplot(perfData_mythril, aes(x = contract, y = execution_time, fill = Tool)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
 # theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

ggsave("mythril-barplot_access_control.pdf", path = "figures/")


#
