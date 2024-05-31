# performance evaluation for lightcross and smartbugs when analysing the smartbugs dataset
source("packages.R")
source("configuration.R")
source("functions.R")
categories <- c(
  "access_control",
  "arithmetic",
  "bad_randomness",
  "denial_of_service",
  "front_running",
  "other",
  "reentrancy",
  "short_addresses",
  "time_manipulation",
  "unchecked_low_level_calls"
)
lightcross_path <- "../../DATA/lightcross/"
smartbugs_path <- "../../DATA/smartbugs/"
figures_path <- "../../figures/"
#perfData <- data_frame()

# process csv files for the path and categories
process_csvs <- function(light_path, smartbugs_path, category) {
  print(trimws(paste(light_path, category, sep = "")))
  #print(trimws(paste(smartbugs_path, category, sep = "")))

  light_csvs <- retrieve_all_csv_files(trimws(paste(light_path, category, sep = "")))
  smartbugs_csvs <- retrieve_all_csv_files(trimws(paste(smartbugs_path, category, sep = "")))

  light_csvs$filename <- basename(light_csvs$File)
print(distinct(light_csvs))

  light_csvs_df <- data.frame(
    contract = light_csvs$filename,
    execution_time = light_csvs$Execution.time,
    scanner = light_csvs$Tool
  )
  df_lightcross <- bind_rows(light_csvs_df, .id = "expID")
  df_lightcross['Tool'] = 'lightcross'

#  print(distinct(df_lightcross))

  smartbugs_csvs$toolid <- ifelse(smartbugs_csvs$toolid == "mythril-0.24.7",
                                  "mythril",
                                  smartbugs_csvs$toolid)

  smartbugs_csvs_df <- data_frame(
    contract = smartbugs_csvs$basename,
    execution_time = smartbugs_csvs$duration,
    scanner = smartbugs_csvs$toolid
  )
  df_smartbugs <- bind_rows(smartbugs_csvs_df, .id = "expID")
  df_smartbugs['Tool'] = 'smartbugs'
  perfData <- rbind(df_lightcross, df_smartbugs)

  #perfData <- distinct(subset(perfData, execution_time <= 4000))
  perfData <- distinct(perfData)
rawData<- distinct(perfData)

  # limit rows to 100
  # perfData<-head(perfData, n = 400)

  ggplot(perfData, aes(x = contract, y = execution_time, fill = Tool)) +
    geom_bar(stat = "identity", position = "dodge") +
    labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
    theme_minimal() +
    theme(axis.text.x = element_text(angle = 45, hjust = 1))
  #ggsave(paste("tools-barplot_", category, ".pdf"), path = "figures/")

  perfData_slither <- distinct(subset(perfData, scanner == "slither"))
  ggplot(perfData_slither,
         aes(x = contract, y = execution_time, fill = Tool)) +
    geom_bar(stat = "identity", position = "dodge") +
    labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
    theme_minimal() +
    theme(axis.text.x = element_text(angle = 45, hjust = 1))

  ggsave(paste("slither-barplot_", category, ".pdf"), path = "figures/")

  perfData_mythril <- distinct(subset(perfData, scanner == "mythril"))
  ggplot(perfData_mythril,
         aes(x = contract, y = execution_time, fill = Tool)) +
    geom_bar(stat = "identity", position = "dodge") +
    labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
    # theme_minimal() +
    theme(axis.text.x = element_text(angle = 45, hjust = 1))

  ggsave(paste("mythril-barplot_", category, ".pdf"), path = "figures/")
  return(df_lightcross)

}

for (category in categories) {
  data <- process_csvs(lightcross_path, smartbugs_path, category)
}








#
