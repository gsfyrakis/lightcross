## ---- measuring execution time for MPGS128 ----
source("packages.R")
source("configuration.R")
source("functions.R")

numberOfVertices <- c("10", "50", "100", "200", "300", "400")
lengthVertices <- length(numberOfVertices)
mpgsPerf <- data.frame()

for (i in seq_along(numberOfVertices)) {
  path <- paste("graph-", numberOfVertices[i], sep = "")
  print(path)
  (csvFile <-
    paste("100+10rounds_graph", numberOfVertices[i], "_10", sep = ""))
  mpgsPerfTemp <-
    createDataSetFromCSV(path, csvFile, numberOfVertices[i])
  mpgsPerfTemp["Vertices"] <- numberOfVertices[i]
  mpgsPerf <- bind_rows(mpgsPerf, mpgsPerfTemp, .id = "expID")
  print(numberOfVertices[i])
}

mpgsPerf <- select(mpgsPerf, -ori.interm.sign, -interm.sign, -final.sign, -init.sign)

mpgsPerf <- select(
  mpgsPerf, round, Vertices, pop, set,  disjoint,
  cover, edge, connected, isolation #,
  # init.sign
)

colnames(mpgsPerf) <- c(
  "round", "Vertices",
  "Graph", "Set",  "Disjoint",
  "Cover", "Edge", "Connected",  "Isolated" #,
  # "Sign"
)

mpgsPerfLong <- melt(mpgsPerf,
  id.vars = c("round", "Vertices"),
  measure.vars = c(
    "Graph", "Set",  "Disjoint",
    "Cover", "Edge", "Connected",  "Isolated" #,
    #"Sign"
  ),
  variable.name = "Method",
  value.name = "Execution Time"
)



(mpgsPerfMean <- data_summary(mpgsPerfLong, varname = "Execution Time", groupnames = c("Method", "Vertices")))

ggplot(mpgsPerfMean, aes(x = reorder(factor(Vertices)), y = mean / 1000, group = Method)) +
  geom_line(aes(linetype = factor(Method), color = factor(Method)), size = .5) +
  geom_point(aes(colour = factor(Method), shape = factor(Method))) +
  scale_shape_manual(values = seq(0, 15)) +
  scale_color_viridis_d() +
  labs(x = "# Vertices n", y = "Execution time (sec)", color = "", shape = "") +
  guides(linetype = "none") +
  theme(
    legend.position = c(0.4, 0.92),
    legend.direction = "horizontal",
    legend.background = element_blank(),
    legend.box.background = element_rect(colour = "black"),
    plot.background = element_blank(),
    # axis.text = element_text(size = 15),
    # axis.title = element_text(size = 15),
    axis.line = element_line(colour = "black"),
    panel.grid.minor = element_blank(),
    panel.border = element_blank()
  )

ggsave("mpgs128-lineplot.pdf", path = "figures", width = 18, height = 20, unit = "cm")
