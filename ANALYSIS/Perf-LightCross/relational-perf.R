## ---- measuring execution time for egocentric networks ----
source("packages.R")
source("configuration.R")
source("functions.R")

numberOfVertices <- c("1", "2", "3", "4", "5", "6", "7", "8", "9", "10")
verticesOfGraphs <- c("18", "13", "7", "16", "99", "15", "10", "12", "35", "51" )
edgesOfGraphs <- c("90", "76", "21", "59", "2458", "85", "45", "61", "396", "946")
lengthVertices <- length(numberOfVertices)
mpgsPerf <- data.frame()

for (i in seq_along(numberOfVertices)) {
  path <- 'social-network' #paste("graph-", numberOfVertices[i], sep = "")
  print(path)
  (csvFile <-
      paste("50+5rounds_graph10_", numberOfVertices[i] , sep = ""))
  mpgsPerfTemp <-
  createDataSetFromCSV(path, csvFile, numberOfVertices[i])
  mpgsPerfTemp['Vertices'] = verticesOfGraphs[i]
  mpgsPerfTemp['Edges'] = edgesOfGraphs[i]
  mpgsPerf <- bind_rows(mpgsPerf, mpgsPerfTemp, .id = "expID")
  print(numberOfVertices[i])

}

mpgsPerf <- select(mpgsPerf, -ori.interm.sign, -interm.sign, -final.sign)
# mpgsPerf <- select(mpgsPerf, round, Vertices,  pop, set, disjoint, cover, edge, connected, isolation, init.sign)
mpgsPerf <- select(mpgsPerf, round, Vertices, Edges, pop, edge, connected, init.sign)

colnames(mpgsPerf) <- c("round", "Vertices", "Edges",
                      "Possession", "Edge", "Connected", "Sign")

mpgsPerfLong <- melt(mpgsPerf,
                     id.vars=c("round", "Vertices", "Edges"),
                     measure.vars=c("Possession", "Edge", "Connected", "Sign"),
                     variable.name="Method",
                     value.name="Execution Time")

mpgsPerfLong$Vertices <- as.numeric(as.character(mpgsPerfLong$Vertices))
mpgsPerfLong$Edges <- as.numeric(as.character(mpgsPerfLong$Edges))
mpgsPerfLong$Graph_Size <- rowSums(mpgsPerfLong[ , c(2,3)], na.rm=TRUE)

(mpgsPerfMean <- data_summary(mpgsPerfLong, varname = "Execution Time", groupnames = c( "Method", "Graph_Size")))

ggplot(mpgsPerfMean, aes(x = Graph_Size, y = mean/1000, group = Method)) +
  geom_line(aes(linetype = factor(Method), color = factor(Method)), size = .5) +
  geom_point(aes(colour = factor(Method), shape = factor(Method))) +
  scale_x_continuous(breaks=seq(0,2580,500), limits = c(0, 2580)) +
  scale_shape_manual(values=seq(0,15))+
  scale_color_viridis_d() +

  labs(x = "Graph size (# Vertices + # Edges)", y = "Execution time (sec)", color = "", shape = "") +
  guides( linetype = "none") +
  theme(legend.position = c(0.4, 0.92),
        legend.direction="horizontal",
        legend.background = element_blank(),
        legend.box.background = element_rect(colour = "black"),
        plot.background = element_blank(),
        # axis.text = element_text(size = 15),
        # axis.title = element_text(size = 15),
        axis.line = element_line(colour = "black"),
        panel.grid.minor = element_blank(),
        panel.border = element_blank())

ggsave("social-lineplot.pdf", path= "figures", width = 18, height = 20, unit = "cm")

