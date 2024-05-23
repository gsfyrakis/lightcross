retrieve_all_csv_files<-function(folder_path){
  csv_files <- list.files(path = folder_path, pattern = "*.csv", full.names = TRUE)
  data_list <- lapply(csv_files, read.csv)
  combined<-do.call(rbind, data_list)
  return (combined)
}

data_summary <- function(data, varname, groupnames) {
  # in case there are spaces in group names
  groupnames <- paste("`", groupnames, "`", sep = "")

  require(plyr)
  summary_func <- function(x, col) {
    c(
      mean = mean(x[[col]], na.rm = TRUE),
      sd = sd(x[[col]], na.rm = TRUE),
      N = length(x[[col]]),
      se = sd(x[[col]], na.rm = TRUE) / sqrt(length(x[[col]]))
    )
  }
  data_sum <-
    ddply(data,
      groupnames,
      .fun = summary_func,
      .inform = TRUE,
      varname
    )
  # data_sum <- rename(data_sum, c("mean" = varname))

  return(data_sum)
}

## read csv files
readCSVs <- function(a_csv) {
  print(a_csv)
  the_data <-
    read.csv(a_csv,
      header = TRUE,
      sep = ",",
      stringsAsFactors = FALSE
    )
}

## create a list of dataframes from csv files
getCSVData <- function(dPattern, path, fPattern) {
  dirs <-
    grep(dPattern, list.dirs(path, recursive = FALSE), value = TRUE)
  lfiles <-
    list.files(
      dirs,
      pattern = fPattern,
      recursive = TRUE,
      full.names = TRUE,
      include.dirs = TRUE
    )
  data <- lapply(lfiles, FUN = readCSVs)
  return(data)
}


## creates a dataframe from the csv files of the experiments
createDataSetFromCSV <- function(csvFolder, csvName, verticesNo) {
  wpath <- getwd()
  wpath <- gsub(pattern = "analysis", replacement = "", wpath)
  fileName <- paste0(csvName, ".csv", collapse = "")
  dataPath <- file.path(wpath, "benchmark", csvFolder, fileName)
  print(dataPath)
  execTimeGraph <- read.csv(dataPath, sep = ",")
  execTimeGraph <- execTimeGraph[-c(1, 2, 3, 4, 5, 6, 7, 8, 9, 10), ]
  return(execTimeGraph)
}

renameHeadings <- function(df, columns) {
  names(df) <- columns
  return(df)
}

savePlot <- function(name, width, height, folderName) {
  wpath <- getwd()
  figureFolder <- file.path(wpath, folderName)

  if (missing(width) &&
    missing(height)) {
    ggsave(name, device = "pdf", path = figureFolder)
  } else if (missing(width)) {
    ggsave(name,
      device = "pdf",
      path = figureFolder,
      height = height
    )
  } else if (missing(height)) {
    ggsave(name,
      device = "pdf",
      path = figureFolder,
      width = width
    )
  } else {
    ggsave(
      name,
      device = "pdf",
      path = figureFolder,
      width = width,
      height = height
    )
  }
}

# save csv file
writeCSV <- function(dataframe, path) {
  write.csv(dataframe, path, row.names = TRUE)
}

# calculate confidence interval (95%) from a normal distribution
calcCI <- function(mean, sd, N, ci = 0.975) {
  error <- (qnorm(ci) * sd) / sqrt(N)
  left <- mean - error
  right <- mean + error
  res <- c(left, right)
  return(res)
  # return(right)
}
