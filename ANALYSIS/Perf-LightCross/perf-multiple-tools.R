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
data_path <- "../../DATA/vulnerabilities.csv"
data_filename <- "vulnerabilities"
figures_path <- "../../figures/"


vulnerabilities_df <- read.csv(data_path)

# Count the number of vulnerabilities per file and per folder
# df_count <- vulnerabilities_df %>%
#   group_by(Filename, Vulnerability) %>%
#   summarise(count_file = n())
#
# # Print the result
# print(df_count)
# write.csv(df_count, "vuln-per-file.csv", row.names = FALSE)


# # Count the number of vulnerabilities per file and per folder
# df_summary <- vulnerabilities_df %>%
#   group_by(Folder, Filename, Vulnerability) %>%
#   summarise(count_file = n()) %>%
#   group_by(Folder) %>%
#   summarise(vulnerabilities_category = sum(count_file))
#
# # Print the result
# print(df_summary)
# write.csv(df_summary, "vuln-per-category.csv", row.names = FALSE)

smartbugs_csvs <- data_frame()
light_csvs <- data_frame()

light_csvs <- combine_csv_files_base_r(trimws(paste(lightcross_path, sep = "")))
light_csvs$filename <- basename(light_csvs$File)
print(distinct(light_csvs))
write.csv(light_csvs, "lightcross-raw.csv", row.names = FALSE)

light_csvs_df <- data.frame(
  contract = light_csvs$filename,
  execution_time = light_csvs$Execution.time,
  scanner = light_csvs$Tool
)
df_lightcross <- bind_rows(light_csvs_df, .id = "expID")
df_lightcross['Tool'] = 'lightcross'

df_lightcross$'Category' <- light_csvs$subfolder

print(distinct(df_lightcross))


smartbugs_csvs <- combine_csv_files_base_r(trimws(paste(smartbugs_path, sep = "")))

write.csv(smartbugs_csvs, "smartbugs-raw.csv", row.names = FALSE)

smartbugs_csvs_df <- data_frame(
  contract = smartbugs_csvs$basename,
  execution_time = smartbugs_csvs$duration,
  scanner = smartbugs_csvs$toolid
)
df_smartbugs <- bind_rows(smartbugs_csvs_df, .id = "expID")
df_smartbugs['Tool'] = 'smartbugs'
df_smartbugs$'Category' <- smartbugs_csvs$subfolder

perfData <- rbind(df_lightcross, df_smartbugs)
perfData <- distinct(perfData)

perfData <- perfData %>%
  mutate(contract = sapply(contract, extract_filename))

perfData$scanner <- ifelse(perfData$scanner == "mythril-0.24.7",
                           "mythril",
                           perfData$scanner)

perfData$scanner <- ifelse(perfData$scanner == "slither-0.10.4",
                           "slither",
                           perfData$scanner)

perfData$Category <- ifelse(perfData$Category == "accesscontrol",
                            "access_control",
                            perfData$Category)

perfData_slither <- distinct(subset(perfData, scanner == "slither" |
                                      scanner == "slither-0.10.4"))
ggplot(perfData_slither,
       aes(x = contract, y = execution_time, fill = Tool)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1)) +
  facet_wrap( ~ Category)

slitherPerfMean <- data_summary(
  perfData_slither,
  varname = "execution_time",
  groupnames = c("scanner", "Category", "Tool")
)

ggplot(slitherPerfMean, aes(x = Category, y = mean, fill = scanner)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Category", y = "Mean Execution Time (sec)", fill = "Tool") +
  theme(axis.text.x = element_text(angle = 45, hjust = 1)) +
  theme_minimal()


perfData_mythril <- distinct(subset(perfData, scanner == "mythril" | scanner == "slither"))
perfData_mythril <- distinct(perfData_mythril)

ggplot(perfData_mythril,
       aes(x = contract, y = execution_time, fill = Tool)) +
  facet_wrap(~Category, scales = "free") +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Contract", y = "Execution Time (sec)", fill = "Tool") +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

mythrilPerfMean <- data_summary(
  perfData_mythril,
  varname = "execution_time",
  groupnames = c("scanner", "Category", "Tool")
)

ggplot(mythrilPerfMean, aes(x = Category, y = mean, fill = Tool)) +
  geom_bar(stat = "identity", position = "dodge") +
  facet_wrap(~scanner, scales = "free") +
  labs(x = "Category", y = "Mean Execution Time (sec)", fill = "Tool") +
  theme(axis.text.x = element_text(angle = 45, hjust = 1)) +
  custom_colors

ggsave(
  "tool-barplot.pdf",
  path = "figures",
 width = 20,
   height = 13,
  unit = "cm"
)

(mythrilPerfMean)

perfData_mythril_filtered <- perfData_mythril %>%
  filter(Category == "access_control")

ggplot(perfData_mythril_filtered,
       aes(x = contract, y = execution_time, fill = Tool)) +
  facet_wrap(~scanner, scales = "free") +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Contract",
       y = "Execution Time (sec)",
       fill = "Tool",
       title = "Execution Time for Access Control Contracts") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

create_category_plot <- function(category_name) {
  filtered_data <- perfData_mythril %>%
    filter(Category == category_name)

  if (nrow(filtered_data) == 0) {
    warning(paste("No data found for category:", category_name))
    return(NULL)
  }

  p <- ggplot(filtered_data,
              aes(x = contract, y = execution_time, fill = Tool)) +
    facet_wrap(~scanner, scales = "free") +
    geom_bar(stat = "identity", position = "dodge") +
    labs(x = "Contract",
         y = "Execution Time (sec)",
         fill = "Tool",
         title = paste("Execution Time for", gsub("_", " ", category_name), "Contracts")) +
    theme_minimal() +
    theme(axis.text.x = element_text(angle = 45, hjust = 1))

  output_file <- paste0("execution_time_", category_name, ".pdf")
  ggsave(output_file, path = "figures",
         width = 18,
         height = 20,
         unit = "cm")

  return(p)
}

plots <- map(categories, create_category_plot)

plots <- plots[!sapply(plots, is.null)]

cat("Created plots for the following categories:\n")
for (i in seq_along(plots)) {
  if (!is.null(plots[[i]])) {
    cat("- ", gsub("_", " ", categories[i]), "\n")
  }
}

if (length(plots) > 0) {
  plots[[1]]
}

for (plot in plots) {
  print(plot)
}

result_df <- perfData

smartbugs_tools <- distinct(subset(result_df, Tool == "smartbugs"))
(
  lightPerfMeanSB <- data_summary(
    smartbugs_tools,
    varname = "execution_time",
    groupnames = c("scanner", "Category")
  )
)

ggplot(lightPerfMeanSB, aes(x = Category, y = mean, fill = scanner)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Category", y = "Execution Time (sec)", fill = "Detector") +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

ggsave(
  "tool-barplot-all-detectors-smartbug.pdf",
  path = "figures",
  width = 18,
  height = 20,
  unit = "cm"
)


(all_detectors_tools <- data_summary(
  result_df,
  varname = "execution_time",
  groupnames = c("scanner", "Tool", "Category")
))

lightPerfMean <- distinct(subset(all_detectors_tools, scanner == "mythril" |
                                   scanner == "slither" | scanner == "mythril-0.24.7"))

ggplot(lightPerfMean, aes(x = Category, y = mean, fill = Tool)) +
  facet_wrap(~scanner, scales = "free") +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Category", y = "Execution Time (sec)", fill = "Tool") +
  theme(axis.text.x = element_text(angle = 45, hjust = 1)) +
  custom_colors


ggsave(
  "tool-barplot-all-tools.pdf",
  path = "figures",
  width = 18,
  height = 20,
  unit = "cm"
)

# hux <- as_hux(perfData)
# print_latex(hux)

lPerfMean <- lightPerfMean[, head(seq_along(lightPerfMean), -3)]
kbl(lPerfMean, booktabs = T, format = "latex")

# hux <- as_hux(perfData)
# print_latex(hux)

perf <- all_detectors_tools[, head(seq_along(all_detectors_tools), -3)]
ltx <- kbl(perf, booktabs = T, format = "latex")
writeLines(ltx, 'smartbugs-all-detector-table.tex')


perfData_slither <- distinct(subset(lightPerfMean, scanner == "slither"))

ggplot(perfData_slither, aes(x = Category, y = mean, fill = Tool)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Category", y = "Mean Execution Time (sec)", fill = "Tool") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

ggsave(
  "slither-barplot.pdf",
  path = "figures",
  width = 18,
  height = 20,
  unit = "cm"
)

perfData_mythril <- distinct(subset(lightPerfMean, scanner == "mythril"))

ggplot(perfData_mythril, aes(x = Category, y = mean, fill = Tool)) +
  geom_bar(stat = "identity", position = "dodge") +
  labs(x = "Category", y = "Mean Execution Time (sec)", fill = "Tool") +
  theme_minimal() +
  theme(axis.title = element_text(
    colour = "black",
    size = 16,
    face = "plain"
  )) +
  theme(axis.text = element_text(
    colour = "black",
    size = 16,
    face = "plain"
  ))  +
  theme(legend.text = element_text(
    colour = "black",
    size = 16,
    face = "plain"
  ))  +
  theme(axis.text.x = element_text(angle = 45, hjust = 1))

ggsave(
  "mythril-barplot.pdf",
  path = "figures",
  width = 18,
  height = 20,
  unit = "cm"
)

