#import "@preview/fletcher:0.5.1" as fletcher: diagram, node, edge

#diagram(
  node((0,0), "VM 1", stroke: 1pt),
  node((1,0), "VM 2", stroke: 1pt),
  edge((0,0), (1,0), "->")
)
