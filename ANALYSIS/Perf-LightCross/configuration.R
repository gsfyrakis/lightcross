options(digits = 3)
options("scipen" = 3)

# configure theme for all plots
theme_set(

  theme_light() +
    theme(
      axis.title = element_text(colour = "black", size = 16, face = "plain"),
      axis.text = element_text(colour = "black", size = 16, face = "plain"),
      strip.text.x = element_text(colour = "black", size = 14, face = "bold"),
      strip.background = element_blank(),
      strip.placement = "outside"
    )

)
custom_colors <- scale_fill_manual(values = c( "#56B4E9", "#E69F00", "#009E73", "#F0E442", "#0072B2", "#D55E00", "#CC79A7"))

# paper folders
paperDataFolderPath <- "../benchmark/"
paperFigureFolderPath <- "../figures/"
paperAnalysisFolderPath <- "../analysis/"
