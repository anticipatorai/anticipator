from wrapper import ObservableCrew


def observe(crew, name: str = "crewai") -> ObservableCrew:
    """
    Wrap a CrewAI Crew with Anticipator threat detection.

    Usage:
        from integrations.crewai import observe

        crew   = Crew(agents=[researcher, writer], tasks=[task1, task2])
        secure = observe(crew, name="my_pipeline")
        result = secure.kickoff()

    All agent.execute_task calls are intercepted automatically.
    No messages are blocked — smoke detector mode only.
    """
    return ObservableCrew(crew, name=name)