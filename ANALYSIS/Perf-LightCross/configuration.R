options(digits = 3)
options("scipen" = 3)

# configure theme for all plots
theme_set(
  theme_light() +
    theme(
      axis.title = element_text(colour = "black", size = 16, face = "plain"),
      axis.text = element_text(colour = "black", size = 16, face = "plain"),
      # strip.text.x = element_text(colour = "black", size = 14, face = "bold"),
      strip.background = element_blank(),
      strip.placement = "outside"
    )
)

# paper folders
paperDataFolderPath <- "../benchmark/"
paperFigureFolderPath <- "../figures/"
paperAnalysisFolderPath <- "../analysis/"
